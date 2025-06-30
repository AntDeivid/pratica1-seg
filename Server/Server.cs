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

            // etapa 1: receber nome de usuario e chave publica do cliente
            Console.WriteLine("Iniciando handshake com o cliente...");
            var clientUsername = await ReadStringAsync(stream);
            Console.WriteLine($"Client username (identificador): {clientUsername}");
            
            var clientPublicKeyPem = await GetKey("AntDeivid", clientUsername);
            if (string.IsNullOrEmpty(clientPublicKeyPem))
            {
                Console.WriteLine($"Chave pública não encontrada para o identificador '{clientUsername}'");
                return;
            }
            
            Console.WriteLine($"Chave pública de '{clientUsername}' obtida com sucesso");

            var clientDhKey = await ReadBytesAsync(stream);
            var clientSignature = await ReadBytesAsync(stream);

            VerifyClientSignature(clientUsername, clientPublicKeyPem, clientDhKey, clientSignature);
            Console.WriteLine("Assinatura do cliente verificada com sucesso");

            // etapa 2: gerar chave DH e enviar chave publica e assinatura
            var (serverPrivateKey, serverPublicKey) = GenerateDhKeyPair();
            var publicKeyBytes = serverPublicKey.ToByteArray(true, true);
            var dataToSign = Combine(publicKeyBytes, Encoding.UTF8.GetBytes(_username));
            var serverSignature = _serverEcdsa.SignData(dataToSign, HashAlgorithmName.SHA256);

            await WriteMessageAsync(stream, Encoding.UTF8.GetBytes(_username));
            await WriteMessageAsync(stream, publicKeyBytes);
            await WriteMessageAsync(stream, serverSignature);
            Console.WriteLine("Chave publica e assinatura do servidor enviadas com sucesso");

            // etapa 3: derivacao de chaves
            var clientPublicKey = new BigInteger(clientDhKey, true, true);
            var sharedSecret = ComputeSharedSecret(clientPublicKey, serverPrivateKey);
            Console.WriteLine("Segredo compartilhado calculado com sucesso");

            var salt = RandomNumberGenerator.GetBytes(16);
            await WriteMessageAsync(stream, salt);
            var (aesKey, hmacKey) = DeriveKeys(sharedSecret, salt);
            Console.WriteLine("Chaves AES e HMAC derivadas com sucesso");

            // etapa 4: receber mensagem
            await ProcessMessage(stream, aesKey, hmacKey);
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine($"Falha de criptografia: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro inesperado: {ex.Message}");
        }
        finally
        {
            Console.WriteLine("Fechando conexão com o cliente...");
            tcpClient.Close();
        }
    }

    private async Task ProcessMessage(NetworkStream stream, byte[] aesKey, byte[] hmacKey)
    {
        Console.WriteLine("\nAguardando mensagem...");
        var encryptedPackage = await ReadBytesAsync(stream);
        
        if (!UnpackMessage(encryptedPackage, out var hmacTag, out var iv, out var ciphertext))
        {
            throw new FormatException("Pacote malformado");
        }
        
        var expectedHmac = ComputeHmac(Combine(iv, ciphertext), hmacKey);

        if (!CryptographicOperations.FixedTimeEquals(hmacTag, expectedHmac))
        {
            throw new CryptographicException("HMAC inválido");
        }
        Console.WriteLine("HMAC verificado com sucesso");
        
        var decryptedMessage = DecryptMessage(ciphertext, aesKey, iv);
        Console.WriteLine($"Mensagem recebida: {decryptedMessage}");
    }
    
    private void VerifyClientSignature(string username, string pemKey, byte[] dhKey, byte[] signature)
    {
        using var clientEcdsa = ECDsa.Create();
        clientEcdsa.ImportFromPem(pemKey);
        var dataToVerify = Combine(dhKey, Encoding.UTF8.GetBytes(username));
        if (!clientEcdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("Assinatura inválida do cliente");
        }
    }
    
    private async Task<string> GetKey(string gitHubUser, string keyIdentifier)
    {
        try
        {
            var url = $"https://github.com/{gitHubUser}.keys";
            var keysFileContent = await _httpClient.GetStringAsync(url);
            var lines = keysFileContent.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            var identifierLine = $"# {keyIdentifier}";

            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Trim() == identifierLine)
                {
                    var pemBuilder = new StringBuilder();
                    for (int j = i + 1; j < lines.Length; j++)
                    {
                        var currentLine = lines[j].Trim();
                        if (currentLine.StartsWith("#")) break;
                        
                        pemBuilder.AppendLine(currentLine);
                        if (currentLine == "-----END PUBLIC KEY-----")
                        {
                            return pemBuilder.ToString();
                        }
                    }
                }
            }
            return string.Empty;
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Falha ao buscar chave para '{gitHubUser}': {e.Message}");
            return string.Empty;
        }
    }
    
    #region funcoes auxiliares
    private static async Task<byte[]> ReadBytesAsync(NetworkStream stream)
    {
        var lengthPrefix = new byte[4];
        await stream.ReadExactlyAsync(lengthPrefix, 0, 4);
        var messageLength = BitConverter.ToInt32(lengthPrefix, 0);
        var message = new byte[messageLength];
        await stream.ReadExactlyAsync(message, 0, messageLength);
        return message;
    }
    private static async Task<string> ReadStringAsync(NetworkStream stream) => Encoding.UTF8.GetString(await ReadBytesAsync(stream));
    private static async Task WriteMessageAsync(NetworkStream stream, byte[] message)
    {
        await stream.WriteAsync(BitConverter.GetBytes(message.Length));
        await stream.WriteAsync(message);
    }
    private static bool UnpackMessage(byte[] package, out byte[] hmacTag, out byte[] iv, out byte[] ciphertext)
    {
        hmacTag = iv = ciphertext = Array.Empty<byte>();
        if (package.Length <= 48) return false;
        hmacTag = package[..32]; iv = package[32..48]; ciphertext = package[48..];
        return true;
    }
    
    private static byte[] ComputeHmac(byte[] data, byte[] key) => HMACSHA256.HashData(key, data);
    
    private static byte[] Combine(byte[] first, byte[] second)
    {
        var ret = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
        return ret;
    }
    
    private static string DecryptMessage(byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        using var decryptor = aes.CreateDecryptor();
        return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length));
    }
    
    private static (BigInteger privateKey, BigInteger publicKey) GenerateDhKeyPair()
    {
        var privateKey = new BigInteger(RandomNumberGenerator.GetBytes(128), true, true);
        var publicKey = BigInteger.ModPow(G, privateKey, P);
        return (privateKey, publicKey);
    }
    
    private static byte[] ComputeSharedSecret(BigInteger otherPublicKey, BigInteger ourPrivateKey)
    {
        return BigInteger.ModPow(otherPublicKey, ourPrivateKey, P).ToByteArray(true, true);
    }
    
    private static (byte[] aesKey, byte[] hmacKey) DeriveKeys(byte[] sharedSecret, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(sharedSecret, salt, 100_000, HashAlgorithmName.SHA256);
        return (pbkdf2.GetBytes(32), pbkdf2.GetBytes(32));
    }
    #endregion
    
    public static async Task Main(string[] args)
    {
        var serverIdentifier = "p1_server";
        var serverPrivateKeyPem = 
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "COLE AQUI O CONTEÚDO DA SUA CHAVE PRIVADA 'server_ecdsa' GERADA LOCALMENTE\n" +
            "-----END EC PRIVATE KEY-----";

        var server = new Server(serverPrivateKeyPem, serverIdentifier);
        await server.StartAsync();
    }
}