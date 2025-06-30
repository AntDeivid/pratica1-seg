using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Client;

public class Client
{
    private readonly ECDsa _clientEcdsa;
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
    
    public Client(string privateKey, string username)
    {
        _clientEcdsa = ECDsa.Create();
        _clientEcdsa.ImportFromPem(privateKey);
        _username = username;
    }

    public async Task RunAsync(string host, int port, string message)
    {
        Console.WriteLine($"Usuario {_username} iniciando conexão com o servidor {host}:{port}...");

        try
        {
            using var tcpClient = new TcpClient(host, port);
            using var stream = tcpClient.GetStream();
            Console.WriteLine("Conexão estabelecida");
            
            // etapa 1: enviar nome de usuario e chave publica
            Console.WriteLine("Iniciando handshake com o servidor...");
            var (clientPrivateKey, clientPublicKey) = GenerateDhKeyPair();
            var clientPublicKeyBytes = clientPublicKey.ToByteArray(true, true);
            var dataToSign = Combine(clientPublicKeyBytes, Encoding.UTF8.GetBytes(_username));
            var signature = _clientEcdsa.SignData(dataToSign, HashAlgorithmName.SHA256);
            
            await WriteMessageAsync(stream, Encoding.UTF8.GetBytes(_username));
            await WriteMessageAsync(stream, clientPublicKeyBytes);
            await WriteMessageAsync(stream, signature);
            Console.WriteLine("Nome de usuário e chave pública enviados com sucesso");
            
            // etapa 2: receber chave publica do servidor e assinatura
            var serverUsername = await ReadStringAsync(stream);
            var serverPublicKeyBytes = await ReadBytesAsync(stream);
            var serverSignature = await ReadBytesAsync(stream);
            Console.WriteLine($"Servidor respondeu com nome de usuário: {serverUsername}");
            
            var serverPublicKeyPem = await GetKey(serverUsername);
            if (string.IsNullOrEmpty(serverPublicKeyPem))
            {
                Console.WriteLine($"Chave pública não encontrada para '{serverUsername}'");
                return;
            }
            Console.WriteLine($"Chave pública de {serverUsername} recebida com sucesso");
            
            VerifyServerSignature(serverUsername, serverPublicKeyPem, clientPublicKeyBytes, serverSignature);
            Console.WriteLine("Assinatura do servidor verificada com sucesso");
            
            // etapa 3: derivacao de chaves
            var serverPublicKey = new BigInteger(serverPublicKeyBytes, true, true);
            var sharedSecret = ComputeSharedSecret(serverPublicKey, clientPrivateKey);
            Console.WriteLine("Segredo compartilhado calculado com sucesso");
            
            var salt = await ReadBytesAsync(stream);
            var (aesKey, hmacKey) = DeriveKeys(sharedSecret, salt);
            Console.WriteLine("Chaves AES e HMAC derivadas com sucesso");
            
            // etapa 4: enviar mensagem
            Console.WriteLine("Enviando mensagem ao servidor...");
            var encryptedMessage = EncryptMessage(message, aesKey, out var iv);
            var hmacTag = ComputeHmac(Combine(iv, encryptedMessage), hmacKey);
            var packedMessage = PackMessage(hmacTag, iv, encryptedMessage);
            await WriteMessageAsync(stream, packedMessage);
            Console.WriteLine("Mensagem enviada com sucesso");
        }
        catch (SocketException e)
        {
            Console.WriteLine($"Erro de conexão: {e.Message}");
        }
        catch (CryptographicException e)
        {
            Console.WriteLine($"Erro criptográfico: {e.Message}");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Erro inesperado: {e.Message}");
        }
    }

    private void VerifyServerSignature(string username, string pemKey, byte[] dhKey, byte[] signature)
    {
        using var serverEcdsa = ECDsa.Create();
        serverEcdsa.ImportFromPem(pemKey);
        var dataToVerify = Combine(dhKey, Encoding.UTF8.GetBytes(username));
        if (!serverEcdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("Assinatura do servidor inválida.");
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
    
    private static byte[] PackMessage(byte[] hmacTag, byte[] iv, byte[] ciphertext)
    {
        var package = new byte[32 + 16 + ciphertext.Length];
        Buffer.BlockCopy(hmacTag, 0, package, 0, 32);
        Buffer.BlockCopy(iv, 0, package, 32, 16);
        Buffer.BlockCopy(ciphertext, 0, package, 48, ciphertext.Length);
        return package;
    }
    
    private static byte[] ComputeHmac(byte[] data, byte[] key) => HMACSHA256.HashData(key, data);
    
    private static byte[] Combine(byte[] first, byte[] second)
    {
        var ret = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
        return ret;
    }

    private static byte[] EncryptMessage(string message, byte[] key, out byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        iv = aes.IV;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(message), 0, message.Length);
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
            Console.WriteLine($"Falha ao buscar chave para '{username}': {e.Message}");
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
        var clientUsername = "seu-usuario-github-cliente";
        var clientPrivateKeyPem = 
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "COLE AQUI O CONTEÚDO DA SUA CHAVE PRIVADA ECDSA EM FORMATO PEM\n" +
            "-----END EC PRIVATE KEY-----";
        var messageToSend = "Cliente e servidor estão com a mesma estrutura. Perfeito!";

        var client = new Client(clientUsername, clientPrivateKeyPem);
        await client.RunAsync("127.0.0.1", 9000, messageToSend);
    }
    
}