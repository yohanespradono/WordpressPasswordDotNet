public class WpPassword
{
    private const string Itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public bool CheckPassword(string password, string storedHash)
    {
        if ( password.Length > 4096 ) {
            return false;
        }
        var hash = WpCryptPrivate(password, storedHash);
        return hash == storedHash;
    }

    public string Generate(string input)
    {
        var salt = WpGenSalt(WpRandomBytes(6));
        return WpCryptPrivate(input, salt);
    }

    private byte[] StringToBytes(string input)
    {
        return System.Text.Encoding.ASCII.GetBytes(input);
    }

    private string WpRandom(int count)
    {
        var output = "";
        var randomState = "";
        
        for (var i = 0; i < count; i += 16) {
            randomState = Md5.Hash(DateTime.Now.Microsecond + randomState); 
            output += Md5.Hash(randomState);
        }
        output = output.Substring(0, count);
        return output;
    }

    // alternative to WpRandom()
    private byte[] WpRandomBytes(int count)
    {
        Random rnd = new Random();
        Byte[] b = new Byte[count];
        rnd.NextBytes(b);
        return b;
    }

    private string WpGenSalt(dynamic input)
    {
        var output = "$P$";
        output += Itoa64[13];
        output += WpEncode64(input, 6);
        return output;
    }
    // wordpress function crypt_private($password, $setting)
    private string WpCryptPrivate(string password, string setting)
    {
        var output = "*0";
        if ( setting.Substring(0, 2) == output)
            output = "*1";
        
        var id = setting.Substring(0, 3);
        // We use "$P$", phpBB3 uses "$H$" for the same thing
        if (id != "$P$" && id != "$H$")
            return output;
        
        var countLog2 = Itoa64.IndexOf(setting[3]);
        if (countLog2 < 7 || countLog2 > 30) return output;
        
        var count = 1 << countLog2;

        var salt = setting.Substring(4, 8);
        if (salt.Length != 8) 
            return output;
                
        var hash = Md5.FromString(salt + password);
        
        do {
            hash = Md5.FromBytes(hash.Concat(StringToBytes(password)).ToArray());
        } while (--count > 0);

        output = setting.Substring(0, 12);
        output += WpEncode64(hash, 16);

        return output;
    }
    private static string WpEncode64(dynamic input, uint count) 
    {
        var output = "";
        var i = 0;
        int value;
        do {
            value = (int) input[i++];
            output += Itoa64[value & 0x3f];
            
            if (i < count)
                value |= (int) input[i] << 8;
            output += Itoa64[(value >> 6) & 0x3f];
            if (i++ >= count)
                break;
            if (i < count)
                value |= (int) input[i] << 16;
            output += Itoa64[(value >> 12) & 0x3f];
            if (i++ >= count)
                break;
            output += Itoa64[(value >> 18) & 0x3f];
        } while (i < count);

        return output;
    }
}
