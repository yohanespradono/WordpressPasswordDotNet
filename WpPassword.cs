public class WpPassword
{
    private const string Itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public bool CheckPassword(string password, string storedHash)
    {
        if ( password.Length > 4096 ) {
            return false;
        }
        string hash = WpCryptPrivate(password, storedHash);
        return hash == storedHash;
    }

    public string Generate(string input)
    {
        string salt = WpGenSalt(WpRandom<string>(6));
        return WpCryptPrivate(input, salt);
    }

    private T WpRandom<T>(int count)
    {
        if (typeof(T) == typeof(Byte[]))
        {
            Random rnd = new Random();
            Byte[] b = new Byte[count];
            rnd.NextBytes(b);
            return System.Runtime.CompilerServices.Unsafe.As<byte[], T>(ref b);
        }
        
        string output = "";
        string randomState = "";
        Random random = new Random();
        
        for (var i = 0; i < count; i += 16) {
            randomState = Md5.Hash(random.Next() + randomState); 
            output += Md5.Hash(randomState);
        }
        output = output.Substring(0, count);
        return System.Runtime.CompilerServices.Unsafe.As<string, T>(ref output);
    }

    private string WpGenSalt<T>(T input)
    {
        byte[] _input;
        if (typeof(T) == typeof(string))
        {
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes((string)(object) input);
            _input = bytes;
        }
        else
        {
            _input = (byte[])(object)input;
        }
        
        string output = "$P$";
        output += Itoa64[13];
        output += WpEncode64(_input, 6);
        return output;
    }
    
    private string WpCryptPrivate(string password, string setting)
    {
        string output = "*0";
        if ( setting.Substring(0, 2) == output)
            output = "*1";
        
        string id = setting.Substring(0, 3);
        // We use "$P$", phpBB3 uses "$H$" for the same thing
        if (id != "$P$" && id != "$H$")
            return output;
        
        int countLog2 = Itoa64.IndexOf(setting[3]);
        if (countLog2 < 7 || countLog2 > 30) return output;
        
        int count = 1 << countLog2;

        string salt = setting.Substring(4, 8);
        if (salt.Length != 8) 
            return output;
                
        byte[] hash = Md5.FromString(salt + password);
        
        do {
            hash = Md5.FromBytes(hash.Concat(StringToBytes(password)).ToArray());
        } while (--count > 0);

        output = setting.Substring(0, 12);
        output += WpEncode64(hash, 16);

        return output;
    }
    private static string WpEncode64<T>(T input, uint count)
    {
        byte[] _input;
        if (typeof(T) == typeof(string))
        {
            _input = System.Text.Encoding.ASCII.GetBytes((string)(object)input);
        }
        else
        {
            _input = (byte[])(object)input;
        }
        
        string output = "";
        int i = 0;
        int value;
        do {
            value = _input[i++];
            output += Itoa64[value & 0x3f];
            if (i < count)
                value |= _input[i] << 8;
            output += Itoa64[(value >> 6) & 0x3f];
            if (i++ >= count)
                break;
            if (i < count)
                value |= _input[i] << 16;
            output += Itoa64[(value >> 12) & 0x3f];
            if (i++ >= count)
                break;
            output += Itoa64[(value >> 18) & 0x3f];
        } while (i < count);

        return output;
    }
    
    private byte[] StringToBytes(string input)
    {
        return System.Text.Encoding.ASCII.GetBytes(input);
    }
}
