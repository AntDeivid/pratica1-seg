using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace pratica1_seg;

public class Server
{
    private readonly ECDsa _serverEcdsa;
    private readonly string _username;
    private readonly HttpClient _httpClient = new();

    private static readonly BigInteger P = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1C" +
        "D129024E088A67CC74020BBEA63B139B22514A08798E3404" +
        "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C2" +
        "45E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7" +
        "EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B" +
        "3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF" +
        "5F83655D23DCA3AD961C62F356208552BB9ED52907709696" +
        "6D670C354E4ABC9804F1746C08CA18217C32905E462E36CE" +
        "3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52" +
        "C9DE2BCBF6955817183995497CEA956AE515D2261898FA05" +
        "1015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA" +
        "64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4" +
        "C7ABF5AE8CDB0933D71E8C94E04A25619DCE3352E0C30572" +
        "967B3767F8959DB70C582B49141BF51011910B1D428989", System.Globalization.NumberStyles.HexNumber);

    private static readonly BigInteger G = new(2);

    public Server(string privateKey, string username)
    {
        _serverEcdsa = ECDsa.Create();
        _serverEcdsa.ImportFromPem(privateKey);
        _username = username;
    }

    public async Task StartAsync(int port = 9000)
    {
        var listener = new TcpListener(System.Net.IPAddress.Any, port);
        listener.Start();
        Console.WriteLine($"Servidor '{_username}' iniciado na porta {port}. Aguardando conexões...");

        while (true)
        {
            var tcpClient = await listener.AcceptTcpClientAsync();
            Console.WriteLine("\nCliente conectado. Iniciando handshake...");
            _ = Task.Run(() => HandleClient(tcpClient));
        }
    }

    private async Task HandleClient(TcpClient tcpClient)
    {
        try
        {
            using var stream = tcpClient.GetStream();
            var clientUsername = await ReadStringAsync(stream);
            Console.WriteLine($"Client username (identificador): {clientUsername}");

            var clientSshKey = await GetSshKeyFromGitHub("AntDeivid", 0); // Pega a primeira chave (índice 0)
            if (string.IsNullOrEmpty(clientSshKey))
            {
                Console.WriteLine("Chave pública SSH do cliente não encontrada no GitHub.");
                return;
            }

            var clientEcdsa = ParseSshKey(clientSshKey);
            Console.WriteLine($"Chave pública de '{clientUsername}' obtida e processada com sucesso");

            var clientDhKey = await ReadBytesAsync(stream);
            var clientSignature = await ReadBytesAsync(stream);

            VerifyClientSignature(clientEcdsa, clientDhKey, clientSignature, clientUsername);
            Console.WriteLine("Assinatura do cliente verificada com sucesso");
            
            var (serverPrivateKey, serverPublicKey) = GenerateDhKeyPair();
            var publicKeyBytes = serverPublicKey.ToByteArray(true, true);
            var dataToSign = Combine(publicKeyBytes, Encoding.UTF8.GetBytes(_username));
            var serverSignature = _serverEcdsa.SignData(dataToSign, HashAlgorithmName.SHA256);

            await WriteMessageAsync(stream, Encoding.UTF8.GetBytes(_username));
            await WriteMessageAsync(stream, publicKeyBytes);
            await WriteMessageAsync(stream, serverSignature);
            Console.WriteLine("Chave pública e assinatura do servidor enviadas com sucesso");

            var clientPublicKey = new BigInteger(clientDhKey, true, true);
            var sharedSecret = ComputeSharedSecret(clientPublicKey, serverPrivateKey);
            var salt = RandomNumberGenerator.GetBytes(16);
            await WriteMessageAsync(stream, salt);
            var (aesKey, hmacKey) = DeriveKeys(sharedSecret, salt);

            await ProcessMessage(stream, aesKey, hmacKey);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro: {ex.GetType().Name} - {ex.Message}");
        }
        finally
        {
            Console.WriteLine("Fechando conexão com o cliente...");
            tcpClient.Close();
        }
    }

    private void VerifyClientSignature(ECDsa clientEcdsa, byte[] dhKey, byte[] signature, string clientUsername)
    {
        // BUG FIX: Usar o username recebido em vez de um valor fixo
        var dataToVerify = Combine(dhKey, Encoding.UTF8.GetBytes(clientUsername));
        if (!clientEcdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("Assinatura inválida do cliente");
        }
    }

    private async Task ProcessMessage(NetworkStream stream, byte[] aesKey, byte[] hmacKey)
    {
        var encryptedPackage = await ReadBytesAsync(stream);
        if (!UnpackMessage(encryptedPackage, out var hmacTag, out var iv, out var ciphertext))
            throw new FormatException("Pacote malformado");
        
        var expectedHmac = ComputeHmac(Combine(iv, ciphertext), hmacKey);
        if (!CryptographicOperations.FixedTimeEquals(hmacTag, expectedHmac))
            throw new CryptographicException("HMAC inválido");
        
        Console.WriteLine("HMAC verificado com sucesso");
        var decryptedMessage = DecryptMessage(ciphertext, aesKey, iv);
        Console.WriteLine($"Mensagem recebida: {decryptedMessage}");
    }

    private async Task<string> GetSshKeyFromGitHub(string gitHubUser, int lineIndex)
    {
        try
        {
            var url = $"https://github.com/{gitHubUser}.keys";
            var keysFileContent = await _httpClient.GetStringAsync(url);
            var lines = keysFileContent.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            return lines.Length > lineIndex ? lines[lineIndex].Trim() : string.Empty;
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Erro ao aceder ao GitHub: {e.Message}");
            return string.Empty;
        }
    }
    
    public static ECDsa ParseSshKey(string sshKey)
    {
        var parts = sshKey.Split(' ');
        if (parts.Length < 2) throw new ArgumentException("Formato de chave SSH inválido.");
    
        var keyData = Convert.FromBase64String(parts[1]);
        using var ms = new MemoryStream(keyData);
        using var reader = new BinaryReader(ms);
    
        byte[] ReadNextField()
        {
            var length = (int)System.Net.IPAddress.NetworkToHostOrder(reader.ReadInt32());
            return reader.ReadBytes(length);
        }
    
        ReadNextField(); // keyType, e.g., "ecdsa-sha2-nistp256", não precisamos dele
        var curveName = Encoding.ASCII.GetString(ReadNextField());
        var publicPointBytes = ReadNextField();
    
        ECCurve curve;
        int keySize;
        switch (curveName)
        {
            case "nistp256": curve = ECCurve.NamedCurves.nistP256; keySize = 32; break;
            case "nistp384": curve = ECCurve.NamedCurves.nistP384; keySize = 48; break;
            case "nistp521": curve = ECCurve.NamedCurves.nistP521; keySize = 66; break;
            default: throw new NotSupportedException($"Curva ECDSA não suportada: {curveName}");
        }
    
        if (publicPointBytes[0] != 0x04)
        {
            throw new NotSupportedException("Formato do ponto da chave pública não suportado. Apenas chaves não comprimidas são aceites.");
        }
        
        var x = new byte[keySize];
        var y = new byte[keySize];
        Buffer.BlockCopy(publicPointBytes, 1, x, 0, keySize);
        Buffer.BlockCopy(publicPointBytes, 1 + keySize, y, 0, keySize);
    
        var ecParams = new ECParameters { Curve = curve, Q = { X = x, Y = y } };
    
        var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(ecParams);
        return ecdsa;
    }

    #region funcoes auxiliares
    private static async Task<byte[]> ReadBytesAsync(NetworkStream stream) { var lengthPrefix = new byte[4]; await stream.ReadExactlyAsync(lengthPrefix, 0, 4); var messageLength = BitConverter.ToInt32(lengthPrefix, 0); var message = new byte[messageLength]; await stream.ReadExactlyAsync(message, 0, messageLength); return message; }
    private static async Task<string> ReadStringAsync(NetworkStream stream) => Encoding.UTF8.GetString(await ReadBytesAsync(stream));
    private static async Task WriteMessageAsync(NetworkStream stream, byte[] message) { await stream.WriteAsync(BitConverter.GetBytes(message.Length)); await stream.WriteAsync(message); }
    private static bool UnpackMessage(byte[] package, out byte[] hmacTag, out byte[] iv, out byte[] ciphertext) { hmacTag = iv = ciphertext = Array.Empty<byte>(); if (package.Length <= 48) return false; hmacTag = package[..32]; iv = package[32..48]; ciphertext = package[48..]; return true; }
    private static byte[] ComputeHmac(byte[] data, byte[] key) => HMACSHA256.HashData(key, data);
    private static byte[] Combine(byte[] first, byte[] second) { var ret = new byte[first.Length + second.Length]; Buffer.BlockCopy(first, 0, ret, 0, first.Length); Buffer.BlockCopy(second, 0, ret, first.Length, second.Length); return ret; }
    private static string DecryptMessage(byte[] cipherText, byte[] key, byte[] iv) { using var aes = Aes.Create(); aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; using var decryptor = aes.CreateDecryptor(); return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length)); }
    private static (BigInteger privateKey, BigInteger publicKey) GenerateDhKeyPair() { var privateKey = new BigInteger(RandomNumberGenerator.GetBytes(128), true, true); var publicKey = BigInteger.ModPow(G, privateKey, P); return (privateKey, publicKey); }
    private static byte[] ComputeSharedSecret(BigInteger otherPublicKey, BigInteger ourPrivateKey) => BigInteger.ModPow(otherPublicKey, ourPrivateKey, P).ToByteArray(true, true);
    private static (byte[] aesKey, byte[] hmacKey) DeriveKeys(byte[] sharedSecret, byte[] salt) { using var pbkdf2 = new Rfc2898DeriveBytes(sharedSecret, salt, 100_000, HashAlgorithmName.SHA256); return (pbkdf2.GetBytes(32), pbkdf2.GetBytes(32)); }
    #endregion
    
    public static async Task Main(string[] args)
    {
        var pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJ+i0IJTGfhVLOJzciHungG1EuKf8r7Gz0Uko+5lTva1oAoGCCqGSM49\nAwEHoUQDQgAEE41TSs1GaWUqLPbEaJGZia8EpXJT4TGF507EInItLJALFg/ih3iv\n3bGQ9okPihAale7NXVgqYpboRlTry3STcw==\n-----END EC PRIVATE KEY-----\n";
        var server = new Server(pem, "p1_server");
        await server.StartAsync();
    }
}