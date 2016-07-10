using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text; 

namespace ConsoleApplication2
{
    class Program
    {
        /*
         This project is a resault of combining two other projects:
         OAEP by mbakkar https://github.com/mbakkar/OAEP and 
         Maciej Lis http://maciejlis.com/rsa-implementation-in-c/
         as well as additional modifications made my me while combining and
         reforming these projects. The resault is a complete RSA implementation
         with OAEP padding.
        */
        static Random random = new Random();
        static byte[] primes;
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Gray;

            Console.Title = "RSA test with OAEP (Optimal asymmetric encryption padding)";
          
            primes = GetNotDividable();
            int p = GenerateRandomPrime((int)Math.Pow(2, 9), (int)Math.Pow(2, 11)), q = GenerateRandomPrime((int)Math.Pow(2, 12), (int)Math.Pow(2, 13));
                                                                                                                                                                         
            uint n = (uint)(p * q);
             
            uint phi = (uint)((p - 1) * (q - 1));
             
            List<uint> possibleE = GetAllPossibleE(phi);
            uint e;
            long d;
            Console.WriteLine("Generating keys...");
            do
            {
                e = possibleE[random.Next(0, possibleE.Count)]; 
                d = ExtendedEuclidean(e % phi, phi).u1;
            } while (d < 0);

             
            Console.WriteLine();

            Console.WriteLine("Public  key: ({0},{1})", n, e);
            Console.WriteLine("Private key: ({0},{1})", n, d);

            Console.WriteLine();
            Console.Write("Enter value to encode: ");
            string raw_value = Console.ReadLine();

            byte[] original_value = Encoding.ASCII.GetBytes(raw_value);
            byte[] value = ApplyOAEP(Encoding.ASCII.GetBytes(raw_value), "SHA-256 MGF1", Encoding.ASCII.GetBytes(raw_value).Length + 32 + 32 + 1);
            int value_length = value.Length;

            int[] encrypted_val = new int[value_length];
            int i = 0;

            // Encryption
            while (i < value_length)
            {
                encrypted_val[i] = (int)ModuloPow(Convert.ToInt32(value[i]), e, n);
                i += 1;
            }
            Console.WriteLine();
            PrintArray("Value = ", value);
            Console.WriteLine();
            PrintArray("Encrypted value = ", encrypted_val);

            // Decryption
            byte[] decrypted_val = new byte[value_length];

            i = 0;
            while (i < value_length)
            {
                decrypted_val[i] = (byte)ModuloPow(encrypted_val[i], d, n);

                i += 1;
            }
            decrypted_val = RemoveOAEP(decrypted_val, "SHA-256 MGF1");

            //Output
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Original message is the same as the decrypted message: "+ original_value.SequenceEqual(decrypted_val));
            Console.ForegroundColor = ConsoleColor.Gray;
        
            Console.WriteLine();
            PrintArray("Decrypted value = ", decrypted_val);
            Console.WriteLine();
            Console.WriteLine("Decrypted text = " + Encoding.ASCII.GetString(decrypted_val.ToArray()));
            Console.ReadKey();
        }
        static byte[] ApplyOAEP(byte[] message, String parameters, int length)
        {
            String[] tokens = parameters.Split(' ');
            if (tokens.Length != 2 || tokens[0] != ("SHA-256") || tokens[1] != ("MGF1"))
            {
                return null;
            }
            int mLen = message.Length;
            int hLen = 32;
            if (mLen > length - (hLen << 1) - 1)
            {
                return null;
            }
            int zeroPad = length - mLen - (hLen << 1) - 1;
            byte[] dataBlock = new byte[length - hLen];
            Array.Copy(SHA256(Encoding.UTF8.GetBytes(parameters)), 0, dataBlock, 0, hLen);
            Array.Copy(message, 0, dataBlock, hLen + zeroPad + 1, mLen);
            dataBlock[hLen + zeroPad] = 1;
            byte[] seed = new byte[hLen];
            random.NextBytes(seed);
            byte[] dataBlockMask = MGF1(seed, 0, hLen, length - hLen);
            for (int i = 0; i < length - hLen; i++)
            {
                dataBlock[i] ^= dataBlockMask[i];
            }
            byte[] seedMask = MGF1(dataBlock, 0, length - hLen, hLen);
            for (int i = 0; i < hLen; i++)
            {
                seed[i] ^= seedMask[i];
            }
            byte[] padded = new byte[length];
            Array.Copy(seed, 0, padded, 0, hLen);
            Array.Copy(dataBlock, 0, padded, hLen, length - hLen);
            return padded;
        }

        static byte[] RemoveOAEP(byte[] message, string parameters)
        {
            string[] tokens = parameters.Split(' ');
            if (tokens.Length != 2 || tokens[0] != ("SHA-256") || tokens[1] != ("MGF1"))
            {
                return null;
            }
            int mLen = message.Length;
            int hLen = 32;
            if (mLen < (hLen << 1) + 1)
            {
                return null;
            }
            byte[] copy = new byte[mLen];
            Array.Copy(message, 0, copy, 0, mLen);
            byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
            for (int i = 0; i < hLen; i++)
            {
                copy[i] ^= seedMask[i];
            }
            byte[] paramsHash = SHA256(Encoding.UTF8.GetBytes(parameters));
            byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
            int index = -1;
            for (int i = hLen; i < mLen; i++)
            {
                copy[i] ^= dataBlockMask[i - hLen];
                if (i < (hLen << 1))
                {
                    if (copy[i] != paramsHash[i - hLen])
                    {
                        return null;
                    }
                }
                else if (index == -1)
                {
                    if (copy[i] == 1)
                    {
                        index = i + 1;
                    }
                }
            }
            if (index == -1 || index == mLen)
            {
                return null;
            }
            byte[] unpadded = new byte[mLen - index];
            Array.Copy(copy, index, unpadded, 0, mLen - index);
            return unpadded;
        }
        static byte[] MGF1(byte[] seed, int seedOffset, int seedLength, int desiredLength)
        {
            int hLen = 32;
            int offset = 0;
            int i = 0;
            byte[] mask = new byte[desiredLength];
            byte[] temp = new byte[seedLength + 4];
            Array.Copy(seed, seedOffset, temp, 4, seedLength);
            while (offset < desiredLength)
            {
                temp[0] = (byte)(i >> 24);
                temp[1] = (byte)(i >> 16);
                temp[2] = (byte)(i >> 8);
                temp[3] = (byte)i;
                int remaining = desiredLength - offset;
                Array.Copy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
                offset = offset + hLen;
                i = i + 1;
            }
            return mask;
        }


        static byte[] SHA256(byte[] input)
        {
            return SHA256Cng.Create().ComputeHash(input);
        }
        static int GenerateRandomPrime(int min_value, int max_value)
        {
            int cn = 0;
            while (true)
            {
                int num = random.Next(min_value, max_value);

                if (isPrime(num))
                {
                    Console.WriteLine("Loops: " + cn + " Prime selected: " + num);
                    return num;
                }
                cn += 1;
            }
        }
        static bool isPrime(int number)
        {
            int boundary = (int)Math.Floor(Math.Sqrt(number));

            if (number == 1) return false;
            if (number == 2) return true;

            for (int i = 2; i <= boundary; ++i)
            {
                if (number % i == 0) return false;
            }

            return true;
        }
        static void PrintArray(string text, int[] arr)
        {
            Console.Write(text);
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write(arr[i] + " ");
            }
            Console.WriteLine();
        }
        static void PrintArray(string text, byte[] arr)
        {
            Console.Write(text);
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write(arr[i] + " ");
            }
            Console.WriteLine();
        }
        static long ModuloPow(long value, long pow, long modulo)
        {
            long result = value;
            for (int i = 0; i < pow - 1; i++)
            {
                result = (result * value) % modulo;
            }
            return result;
        }

        /// <returns>All possible values ​​for the variable e</returns>
        static List<uint> GetAllPossibleE(uint phi)
        {
            List<uint> result = new List<uint>();

            for (uint i = 2; i < phi; i++)
            {
                if (ExtendedEuclidean(i, phi).gcd == 1)
                {
                    result.Add(i);
                }
            }

            return result;
        }

        /// <summary>
        /// u1 * a + u2 * b = u3
        /// </summary>
        /// <param name="a">first number</param>
        /// <param name="b">second number</param>
        static ExtendedEuclideanResult ExtendedEuclidean(long a, long b)
        {
            long u1 = 1;
            long u3 = a;
            long v1 = 0;
            long v3 = b;

            while (v3 > 0)
            {
                long q0 = u3 / v3;
                long q1 = u3 % v3;

                long tmp = v1 * q0;
                long tn = u1 - tmp;
                u1 = v1;
                v1 = tn;

                u3 = v3;
                v3 = q1;
            }

            long tmp2 = u1 * (a);
            tmp2 = u3 - (tmp2);
            long res = tmp2 / (b);

            ExtendedEuclideanResult result = new ExtendedEuclideanResult()
            {
                u1 = u1,
                u2 = res,
                gcd = u3
            };

            return result;
        }

        struct ExtendedEuclideanResult
        {
            public long u1;
            public long u2;
            public long gcd;
        }

        static private byte[] GetNotDividable()
        {
            List<byte> notDivideable = new List<byte>();

            for (int x = 2; x < 256; x++)
            {
                int n = 0;
                for (int y = 1; y <= x; y++)
                {
                    if (x % y == 0)
                        n++;
                }

                if (n <= 2)
                    notDivideable.Add((byte)x);
            }
            return notDivideable.ToArray();
        }

    }
}
