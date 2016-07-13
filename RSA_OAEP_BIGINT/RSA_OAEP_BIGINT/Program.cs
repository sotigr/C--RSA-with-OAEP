using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RSA_OAEP_BIGINT
{
    static class Program
    {
        //static int prime_length = 128;  //---- RSA 256 
        //static int prime_length = 256;  //---- RSA 512 
        static int prime_length = 512;  //---- RSA 1024
        //static int prime_length = 1024; //---- RSA 2048
        //static int prime_length = 2048; //---- RSA 4096
        static void Main(string[] args)
        {
            Console.WriteLine("Please wait.....");
            Stopwatch timer = new Stopwatch();

            timer.Start();

            BigInteger p, q, n, phi, e, d;

            Console.WriteLine("Searching for prime numbers...");

            p = GenerateRandomPrime(prime_length);
            q = GenerateRandomPrime(prime_length);

            n = p * q;

            phi = (p - 1) * (q - 1);

            Console.WriteLine("Generating keys...");
            do
            {
                e = GenerateRandomCoprime(phi);
                d = ExtendedEuclidean(e % phi, phi).u1;
            } while (d < 0);

            Console.WriteLine("\np = " + p.ToString());
            Console.WriteLine("\nq = " + q.ToString());
            Console.WriteLine("\nn = " + n.ToString());
            Console.WriteLine("\nKey bits = " + n.ToByteArray().Length * 8);
            Console.WriteLine("\nphi = " + phi.ToString());
            Console.WriteLine("\ne = " + e.ToString());
            Console.WriteLine("\nd = " + d.ToString());

            timer.Stop();

            Console.Write("\nTime elapsed: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write(timer.ElapsedMilliseconds + " ms\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            timer.Reset();

            Console.WriteLine("\n---------------------------------------------------------------------\n");

            bool procced = true;
            if (n.ToByteArray().Length * 8 != prime_length * 2)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error with big prime detection...");
                Console.ReadLine();
                procced = false;
            }
            if (procced)
            { 
                string input; 
                do
                {
                    Console.Write("Message: ");
                    input = Console.ReadLine();
                    Console.WriteLine();
                } while (input.Trim() == "");

                byte[] message = Encoding.UTF8.GetBytes(input);

                int message_length = message.Length;
                 
                BigInteger[] encrtypted = Encrypt(ApplyOAEP(message, "SHA-256 MGF1", message_length + 32 + 32 + 1), e, n);

                Console.WriteLine("\nEncrypted message raw: ");
                foreach (BigInteger intg in encrtypted)
                {
                    Console.Write(intg.ToString());
                }
                Console.WriteLine();

                byte[] decrtypted = RemoveOAEP(Decrypt(encrtypted, d, n), "SHA-256 MGF1");

                Console.WriteLine("\nDecrypted message: " + Encoding.UTF8.GetString(decrtypted));

                Console.ReadLine();
            }
        }
        static BigInteger[] Encrypt(byte[] plaintext, BigInteger e, BigInteger n)
        {
            int pt_ln = plaintext.Length;
            List<BigInteger> res = new List<BigInteger>();

            List<BigInteger> res_ts_0 = new List<BigInteger>();
            List<BigInteger> res_ts_1 = new List<BigInteger>();
            List<BigInteger> res_ts_2 = new List<BigInteger>();
            List<BigInteger> res_ts_3 = new List<BigInteger>();

            int task_share = pt_ln / 4;

            int task0_cycles = task_share;
            int task1_cycles = task_share * 2;
            int task2_cycles = task_share * 3;
            int task3_cycles = pt_ln;

            Task t0 = Task.Factory.StartNew(() =>
            {
                for (int i = 0; i < task0_cycles; i++)
                {
                    res_ts_0.Add(BigInteger.ModPow(plaintext[i], e, n));
                }
            });
            Task t1 = Task.Factory.StartNew(() =>
            {
                for (int i = task0_cycles; i < task1_cycles; i++)
                {
                    res_ts_1.Add(BigInteger.ModPow(plaintext[i], e, n));
                }
            });
            Task t2 = Task.Factory.StartNew(() =>
            {
                for (int i = task1_cycles; i < task2_cycles; i++)
                {
                    res_ts_2.Add(BigInteger.ModPow(plaintext[i], e, n));
                }
            });
            Task t3 = Task.Factory.StartNew(() =>
            {
                for (int i = task2_cycles; i < task3_cycles; i++)
                {
                    res_ts_3.Add(BigInteger.ModPow(plaintext[i], e, n));
                }
            });

            t0.Wait();
            t1.Wait();
            t2.Wait();
            t3.Wait();

            res.AddRange(res_ts_0);
            res.AddRange(res_ts_1);
            res.AddRange(res_ts_2);
            res.AddRange(res_ts_3);

            return res.ToArray();
        }
        static byte[] Decrypt(BigInteger[] plaintext, BigInteger d, BigInteger n)
        {
            int pt_ln = plaintext.Length;
            List<byte> res = new List<byte>();

            List<byte> res_ts_0 = new List<byte>();
            List<byte> res_ts_1 = new List<byte>();
            List<byte> res_ts_2 = new List<byte>();
            List<byte> res_ts_3 = new List<byte>();

            int task_share = pt_ln / 4;

            int task0_cycles = task_share;
            int task1_cycles = task_share * 2;
            int task2_cycles = task_share * 3;
            int task3_cycles = pt_ln;

            Task t0 = Task.Factory.StartNew(() =>
            {
                for (int i = 0; i < task0_cycles; i++)
                {
                    res_ts_0.Add((byte)BigInteger.ModPow(plaintext[i], d, n));
                }
            });
            Task t1 = Task.Factory.StartNew(() =>
            {
                for (int i = task0_cycles; i < task1_cycles; i++)
                {
                    res_ts_1.Add((byte)BigInteger.ModPow(plaintext[i], d, n));
                }
            });
            Task t2 = Task.Factory.StartNew(() =>
            {
                for (int i = task1_cycles; i < task2_cycles; i++)
                {
                    res_ts_2.Add((byte)BigInteger.ModPow(plaintext[i], d, n));
                }
            });
            Task t3 = Task.Factory.StartNew(() =>
            {
                for (int i = task2_cycles; i < task3_cycles; i++)
                {
                    res_ts_3.Add((byte)BigInteger.ModPow(plaintext[i], d, n));
                }
            });

            t0.Wait();
            t1.Wait();
            t2.Wait();
            t3.Wait();

            res.AddRange(res_ts_0);
            res.AddRange(res_ts_1);
            res.AddRange(res_ts_2);
            res.AddRange(res_ts_3);

            return res.ToArray();
        }

        static ExtendedEuclideanResult ExtendedEuclidean(BigInteger a, BigInteger b)
        {
            BigInteger x0 = 1, xn = 1;
            BigInteger y0 = 0, yn = 0;
            BigInteger x1 = 0;
            BigInteger y1 = 1;
            BigInteger q;
            BigInteger r = a % b;

            while (r > 0)
            {
                q = a / b;
                xn = x0 - q * x1;
                yn = y0 - q * y1;

                x0 = x1;
                y0 = y1;
                x1 = xn;
                y1 = yn;
                a = b;
                b = r;
                r = a % b;
            }

            return new ExtendedEuclideanResult()
            {
                u1 = xn,
                u2 = yn,
                gcd = b
            };
        }

        struct ExtendedEuclideanResult
        {
            public BigInteger u1;
            public BigInteger u2;
            public BigInteger gcd;
        }
        static BigInteger GenerateRandomCoprime(BigInteger number)
        {
            bool found = false;
            BigInteger resault = BigInteger.Zero;
            while (!found)
            {
                resault = GenerateRandomPrime(prime_length - 1, 10);
                if (Coprime(number, resault))
                    found = true;
            }
            return resault;
        }

        static BigInteger GenerateRandomPrime(int length, int witnesses = 10, int tasks = 6)
        {
            bool flag = false;
            BigInteger num = BigInteger.Zero;
            while (!flag)
            {
                List<Task> tl = new List<Task>();
                for (int i = 0; i < tasks; i++)
                {
                    tl.Add(Task.Factory.StartNew(() =>
                    {
                        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                        byte[] bytes = new byte[length / 8];
                        rng.GetBytes(bytes);

                        BigInteger p = new BigInteger(bytes);

                        bool isprime = p.IsProbablyPrime(witnesses);
                        if (isprime)
                        {
                            num = p;
                            flag = true;
                        }

                    }));
                }
                for (int i = 0; i < tasks - 1; i++)
                {
                    tl[i].Wait();
                }

                tl.Clear();
            }
            return num;
        }


        static BigInteger GetGCDByModulus(BigInteger value1, BigInteger value2)
        {
            while (value1 != 0 && value2 != 0)
            {
                if (value1 > value2)
                    value1 %= value2;
                else
                    value2 %= value1;
            }
            return BigInteger.Max(value1, value2);
        }

        static bool Coprime(BigInteger value1, BigInteger value2)
        {
            return GetGCDByModulus(value1, value2).IsOne;
        }

        static byte[] ApplyOAEP(byte[] message, String parameters, int length)
        {
            Random random = new Random();
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
    }

    public static class PrimeExtensions
    { 
        private static ThreadLocal<Random> s_Gen = new ThreadLocal<Random>(
          () =>
          {
              return new Random();
          }
        );
         
        private static Random Gen
        {
            get
            {
                return s_Gen.Value;
            }
        }

        public static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1)
                return false;

            if (witnesses <= 0)
                witnesses = 10;

            BigInteger d = value - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    Gen.NextBytes(bytes);

                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= value - 2);

                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);

                    if (x == 1)
                        return false;
                    if (x == value - 1)
                        break;
                }

                if (x != value - 1)
                    return false;
            }

            return true;
        }
    }
}