public class Md5
{
    public static string Hash(string input)
    {
        return Convert.ToHexString(FromString(input));
    }
    public static byte[] FromString(string input)
    {
        // Use input string to calculate MD5 hash
        using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input); // convert string to byte[]
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            return hashBytes;
        }
    }
    public static byte[] FromBytes(byte[] inputBytes)
    {
        // Use input string to calculate MD5 hash
        using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            return hashBytes;
        }
    }
}
