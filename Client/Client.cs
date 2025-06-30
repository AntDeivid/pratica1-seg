using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Client;

public class Client
{
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
        "967B3767F8959DB70C582B49141BF51011910B1D428989",
        NumberStyles.HexNumber);

    private static readonly BigInteger G = new(2);
    private readonly ECDsa _clientEcdsa;
    private readonly HttpClient _httpClient = new();
    private readonly string _username;

    public Client(string privateKey, string username)
    {
        _clientEcdsa = ECDsa.Create();
        _clientEcdsa.ImportFromPem(privateKey);
        _username = username;
    }

    public async Task RunAsync(string host, int port, string message)
    {
        try
        {
            using var tcpClient = new TcpClient(host, port);
            using var stream = tcpClient.GetStream();
            Console.WriteLine("Conexão estabelecida");

            var (clientPrivateKey, clientPublicKey) = GenerateDhKeyPair();
            var clientPublicKeyBytes = clientPublicKey.ToByteArray(true, true);
            var dataToSign = Combine(clientPublicKeyBytes, Encoding.UTF8.GetBytes(_username));
            var signature = _clientEcdsa.SignData(dataToSign, HashAlgorithmName.SHA256);

            await WriteMessageAsync(stream, Encoding.UTF8.GetBytes(_username));
            await WriteMessageAsync(stream, clientPublicKeyBytes);
            await WriteMessageAsync(stream, signature);
            Console.WriteLine("Nome de usuário e chave pública DH enviados com sucesso");

            var serverUsername = await ReadStringAsync(stream);
            var serverPublicKeyBytes = await ReadBytesAsync(stream);
            var serverSignature = await ReadBytesAsync(stream);
            Console.WriteLine($"Servidor respondeu com nome de usuário: {serverUsername}");

            var serverSshKey = await GetSshKeyFromGitHub("AntDeivid", 1); // Pega a segunda chave (índice 1)
            if (string.IsNullOrEmpty(serverSshKey))
            {
                Console.WriteLine("Chave pública SSH do servidor não encontrada no GitHub.");
                return;
            }

            var serverEcdsa = ParseSshKey(serverSshKey);
            Console.WriteLine($"Chave pública de '{serverUsername}' obtida e processada com sucesso");

            VerifyServerSignature(serverEcdsa, serverPublicKeyBytes, serverSignature, serverUsername);
            Console.WriteLine("Assinatura do servidor verificada com sucesso");

            var serverPublicKey = new BigInteger(serverPublicKeyBytes, true, true);
            var sharedSecret = ComputeSharedSecret(serverPublicKey, clientPrivateKey);
            var salt = await ReadBytesAsync(stream);
            var (aesKey, hmacKey) = DeriveKeys(sharedSecret, salt);

            var encryptedMessage = EncryptMessage(message, aesKey, out var iv);
            var hmacTag = ComputeHmac(Combine(iv, encryptedMessage), hmacKey);
            var packedMessage = PackMessage(hmacTag, iv, encryptedMessage);
            await WriteMessageAsync(stream, packedMessage);
            Console.WriteLine("Mensagem enviada com sucesso");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Erro: {e.GetType().Name} - {e.Message}");
        }
    }

    private void VerifyServerSignature(ECDsa serverEcdsa, byte[] dhKey, byte[] signature, string serverUsername)
    {
        var dataToVerify = Combine(dhKey, Encoding.UTF8.GetBytes(serverUsername));
        if (!serverEcdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256))
            throw new CryptographicException("Assinatura do servidor inválida.");
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
            var length = IPAddress.NetworkToHostOrder(reader.ReadInt32());
            return reader.ReadBytes(length);
        }

        ReadNextField();
        var curveName = Encoding.ASCII.GetString(ReadNextField());
        var publicPointBytes = ReadNextField();

        ECCurve curve;
        int keySize;
        switch (curveName)
        {
            case "nistp256":
                curve = ECCurve.NamedCurves.nistP256;
                keySize = 32;
                break;
            case "nistp384":
                curve = ECCurve.NamedCurves.nistP384;
                keySize = 48;
                break;
            case "nistp521":
                curve = ECCurve.NamedCurves.nistP521;
                keySize = 66;
                break;
            default: throw new NotSupportedException($"Curva ECDSA não suportada: {curveName}");
        }

        if (publicPointBytes[0] != 0x04)
            throw new NotSupportedException(
                "Formato do ponto da chave pública não suportado. Apenas chaves não comprimidas são aceites.");

        var x = new byte[keySize];
        var y = new byte[keySize];
        Buffer.BlockCopy(publicPointBytes, 1, x, 0, keySize);
        Buffer.BlockCopy(publicPointBytes, 1 + keySize, y, 0, keySize);

        var ecParams = new ECParameters { Curve = curve, Q = { X = x, Y = y } };

        var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(ecParams);
        return ecdsa;
    }

    public static async Task Main(string[] args)
    {
        var pem =
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIFdru+mrXpcNpjbehsdXZys6X2yJRjL4BOKoEOltbG6SoAoGCCqGSM49\n" +
            "AwEHoUQDQgAE11631FjerpIpNGfHIAilRHeKDq9m5MNsZHryOBc5mI1WCEvGHsDW\n" +
            "AnpTlERNtItftw9OYGQswG+b9ZrfihMqGA==\n" +
            "-----END EC PRIVATE KEY-----";
        var client = new Client(pem, "p1_client");
        await client.RunAsync("127.0.0.1", 9000, "Teste final com parse de chave SSH!");
    }

    #region Funções Auxiliares

    private static async Task<byte[]> ReadBytesAsync(NetworkStream stream)
    {
        var lengthPrefix = new byte[4];
        await stream.ReadExactlyAsync(lengthPrefix, 0, 4);
        var messageLength = BitConverter.ToInt32(lengthPrefix, 0);
        var message = new byte[messageLength];
        await stream.ReadExactlyAsync(message, 0, messageLength);
        return message;
    }

    private static async Task<string> ReadStringAsync(NetworkStream stream)
    {
        return Encoding.UTF8.GetString(await ReadBytesAsync(stream));
    }

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

    private static byte[] ComputeHmac(byte[] data, byte[] key)
    {
        return HMACSHA256.HashData(key, data);
    }

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
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        iv = aes.IV;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(message), 0, message.Length);
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
}