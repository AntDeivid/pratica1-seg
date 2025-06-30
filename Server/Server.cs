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
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
        "FFFFFFFFFFFFFFFF", System.Globalization.NumberStyles.HexNumber);
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
        Console.WriteLine($"Servidor iniciado na porta {port}. Aguardando conexões...");

        while (true)
        {
            var tcpClient = await listener.AcceptTcpClientAsync();
            Console.WriteLine("Cliente conectado. Iniciando handshake...");
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
            Console.WriteLine($"Client username: {clientUsername}");

            var clientPublicKeyPem = await GetKey(clientUsername);
            if (string.IsNullOrEmpty(clientPublicKeyPem))
            {
                Console.WriteLine($"Chave pública não encontrada para '{clientUsername}'");
                return;
            }

            Console.WriteLine($"Chave pública de {clientUsername} recebida com sucesso");

            var clientDhKey = await ReadBytesAsync(stream);
            var clientSignature = await ReadBytesAsync(stream);

            VerifyClientSignature(clientUsername, clientPublicKeyPem, clientDhKey, clientSignature);
            Console.WriteLine("Assinatura do cliente verificada com sucesso");

            // etapa 2: gerar chave DH e enviar chave publica e assinatura
            var (serverPrivateKey, serverPublicKey) = GenerateDhKeyPair();
            var publicKeyBytes = serverPublicKey.ToByteArray(true, true);
            var dataToSign = Combine(Encoding.UTF8.GetBytes(_username), publicKeyBytes);
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
            Console.WriteLine("Fechando handshake com o cliente...");
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
        var dataToVerify = Combine(Encoding.UTF8.GetBytes(username), dhKey);
        if (!clientEcdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("Assinatura inválida do cliente");
        }
    }
    
    /// <summary>
    /// metodos auxiliares
    /// </summary>
    
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
        hmacTag = iv = ciphertext = [];
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
    
    private async Task<string> GetKey(string username)
    {
        try
        {
            var response = await _httpClient.GetAsync($"https://github.com/{username}.keys");
            response.EnsureSuccessStatusCode();
            var keysText = await response.Content.ReadAsStringAsync();
            return keysText.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)[0];
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"[ERRO] Falha ao buscar chave para '{username}': {e.Message}");
            return string.Empty;
        }
    }
    
    private static (BigInteger privateKey, BigInteger publicKey) GenerateDhKeyPair()
    {
        var privateKey = new BigInteger(RandomNumberGenerator.GetBytes(256), true, true);
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
    
    public static async Task Main(string[] args)
    {
        var serverUsername = "seu-usuario-github-servidor";
        var serverPrivateKeyPem = 
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "COLE AQUI O CONTEÚDO DA SUA CHAVE PRIVADA ECDSA EM FORMATO PEM\n" +
            "-----END EC PRIVATE KEY-----";

        var server = new Server(serverPrivateKeyPem, serverUsername);
        await server.StartAsync();
    }
}