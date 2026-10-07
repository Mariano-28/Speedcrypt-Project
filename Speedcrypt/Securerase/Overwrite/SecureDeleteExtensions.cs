// Speedcrypt software - The Open-Source for encrypt and decrypt files
// Copyright (C) 2024-2026 Mariano Ortu <https://www.speedcrypt.info/>
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//https://www.gnu.org/licenses/gpl-3.0.html

using System;
using System.IO;

namespace Speedcrypt.Secureerase.Overwrite
{
    /// <summary>
    /// Created by Josip Habjan
    /// 
    /// Integrated into Speedcrypt framework by Mariano Ortu, who thanks the author for this valuable implementation.
    /// OverwriteAlgorithm and SecureDeleteExtensions: robust file erasure methods supporting Quick, Random, DoD, and Gutmann algorithms.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Safe overwrite of files and directories using multiple algorithms
    /// - Buffering large files efficiently
    /// - Thread-safe randomization for overwrite patterns
    ///
    /// Responsibility for integration and validation within Speedcrypt
    /// lies entirely with Mariano Ortu, while respecting the original author's work.
    /// </remarks>

    #region OverwriteAlgorithm

    public enum OverwriteAlgorithm : int
    {
        
        Quick = 1,
        /// <summary>
        /// 1 pass.
        /// This method will simply overwrite a file with zeros before deleting it.
        /// It is not secure and should only be used for unimportant files and for quick free space locks.
        /// </summary>
        
        Random = 2,
        /// <summary>
        /// 1 pass.
        /// This method will simply overwrite a file one time with random data before deleting it.
        /// It is not secure and should only be used for unimportant files.
        /// </summary>
        
        DoD_3 = 4,
        /// <summary>
        /// 3 passes.
        /// This method is based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (DoD 5220.22-M E).  
        /// It will overwrite a file 3 times.  This method offers medium security, use it only on files that do not contain sensitive information.
        /// </summary>
        
        DoD_7 = 8,
        /// <summary>
        /// 7 passes.
        /// This method is based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (US DoD 5220.22-M ECE).  
        /// It will overwrite a file 7 times.  This method incorporates the DoD-3 method.  It is secure and should be used for general files.
        /// </summary>
        
        Gutmann = 16
        /// <summary>
        /// 35 passes.
        /// This method is based on Peter Gutmann's article 'Secure Deletion of Data From Magnetic and Solid-State Memory.'  
        /// The data will be overwritten 35 times using the patterns and methods described in the article.  
        /// While this method takes the longest amount of time, it is the most secure method available and should be used for all files that contain sensitive information.
        /// </summary>
    }

    #endregion

    public static class SecureDeleteExtensions
    {
        #region Private constants

        private const int MAX_BUFFER_SIZE = 67108864;

        #endregion

        #region Delete - DirectoryInfo

        /// <summary>
        /// Safe delete this directory, subdirectories and all the files under this directory.
        /// </summary>
        /// <param name="directory">The DirectoryInfo.</param>
        /// <param name="overwriteAlgorithm">Overwrite algorithm.</param>
        public static void Delete(this DirectoryInfo directory, OverwriteAlgorithm overwriteAlgorithm)
        {
            FileInfo[] files = directory.GetFiles();

            foreach (FileInfo file in files)
            {
                file.Delete(overwriteAlgorithm);
            }

            DirectoryInfo[] subDirectories = directory.GetDirectories();

            foreach (DirectoryInfo subDirectory in subDirectories)
            {
                subDirectory.Delete(overwriteAlgorithm);
            }

            directory.Delete();
        }

        #endregion

        #region Delete - FileInfo

        public static void Delete(this FileInfo file, OverwriteAlgorithm overwriteAlgorithm)
        {
            if ((overwriteAlgorithm & OverwriteAlgorithm.Gutmann) == OverwriteAlgorithm.Gutmann)
            {
                OverwriteFile_Gutmann(file);
            }

            if ((overwriteAlgorithm & OverwriteAlgorithm.DoD_7) == OverwriteAlgorithm.DoD_7)
            {
                OverwriteFile_DoD_7(file);
            }

            if ((overwriteAlgorithm & OverwriteAlgorithm.DoD_3) == OverwriteAlgorithm.DoD_3)
            {
                OverwriteFile_DoD_3(file);
            }

            if ((overwriteAlgorithm & OverwriteAlgorithm.Random) == OverwriteAlgorithm.Random)
            {
                OverwriteFile_Random(file);
            }

            if ((overwriteAlgorithm & OverwriteAlgorithm.Quick) == OverwriteAlgorithm.Quick)
            {
                OverwriteFile_Quick(file);
            }

            file.Delete();
        }

        #endregion

        #region OverwriteFile_Quick

        /// <summary>
        /// Overwrite the file with zero bytes.
        /// </summary>
        /// <param name="file">The file.</param>
        internal static void OverwriteFile_Quick(FileInfo file)
        {
            FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.None);

            for (long size = fs.Length; size > 0; size -= MAX_BUFFER_SIZE)
            {
                long bufferSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;

                byte[] buffer = new byte[bufferSize];

                fs.Write(buffer, 0, buffer.Length);
                fs.Flush(true);
            }

            fs.Close(); fs.Dispose(); fs = null;
        }

        #endregion

        #region OverwriteFile_Random

        /// <summary>
        /// Overwrite the file with random data.
        /// </summary>
        /// <param name="file">The file.</param>
        internal static void OverwriteFile_Random(FileInfo file)
        {
            Random random = ThreadSafeRandom.Random;

            FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.None);

            for (long size = fs.Length; size > 0; size -= MAX_BUFFER_SIZE)
            {
                long bufferSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;

                byte[] buffer = new byte[bufferSize];

                for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                {
                    buffer[bufferIndex] = (byte)(random.Next() % 256);
                }

                fs.Write(buffer, 0, buffer.Length);
                fs.Flush(true);
            }

            fs.Close(); fs.Dispose(); fs = null;
        }

        #endregion

        #region OverwriteFile_DoD_3

        /// <summary>
        /// Overwrite the file based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (DoD 5220.22-M E).
        /// </summary>
        /// <param name="file">The file.</param>
        internal static void OverwriteFile_DoD_3(FileInfo file)
        {
            byte[] pattern = new byte[] { 0x00, 0xFF, 0x72 };

            ThreadSafeRandom.Shuffle<byte>(pattern);

            Random random = ThreadSafeRandom.Random;

            FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.None);

            //for (int pass = 1; pass <= 3; ++pass) Original line with bug
            for (int pass = 0; pass <= 2; ++pass)
            {
                fs.Position = 0;

                for (long size = fs.Length; size > 0; size -= MAX_BUFFER_SIZE)
                {
                    long bufferSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;

                    byte[] buffer = new byte[bufferSize];

                    if (pass != 2)
                    {
                        for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                        {
                            buffer[bufferIndex] = pattern[pass];
                        }
                    }
                    else
                    {
                        for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                        {
                            buffer[bufferIndex] = (byte)(random.Next() % 256);
                        }
                    }

                    fs.Write(buffer, 0, buffer.Length);
                    fs.Flush(true);
                }
            }

            fs.Close(); fs.Dispose(); fs = null;
        }

        #endregion

        #region OverwriteFile_DoD_7

        /// <summary>
        /// Overwrite the file based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (US DoD 5220.22-M ECE).
        /// </summary>
        /// <param name="file">The file.</param>
        internal static void OverwriteFile_DoD_7(FileInfo file)
        {
            byte[] pattern = new byte[] { 0x00, 0xFF, 0x72, 0x96, 0x00, 0xFF, 0x72 };

            ThreadSafeRandom.Shuffle<byte>(pattern);

            Random random = ThreadSafeRandom.Random;

            FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.None);

            //for (int pass = 1; pass <= 7; ++pass) Original line with bug **********************************************************************************************
            for (int pass = 0; pass <= 6; ++pass)
            {
                fs.Position = 0;

                for (long size = fs.Length; size > 0; size -= MAX_BUFFER_SIZE)
                {
                    long bufferSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;

                    byte[] buffer = new byte[bufferSize];

                    if (pass != 2 && pass != 6)
                    {
                        for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                        {
                            buffer[bufferIndex] = pattern[pass];
                        }
                    }
                    else
                    {
                        for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                        {
                            buffer[bufferIndex] = (byte)(random.Next() % 256);
                        }
                    }

                    fs.Write(buffer, 0, buffer.Length);
                    fs.Flush(true);
                }
            }

            fs.Close(); fs.Dispose(); fs = null;
        }

        #endregion

        #region OverwriteFile_Gutmann

        /// <summary>
        /// Overwrite the file based on the Peter Gutmann's algorithm.
        /// </summary>
        /// <param name="file">The file.</param>
        internal static void OverwriteFile_Gutmann(FileInfo file)
        {
            byte[][] pattern = new byte[][] { 
                new byte[] {0x55, 0x55, 0x55}, new byte[] {0xAA, 0xAA, 0xAA}, new byte[] {0x92, 0x49, 0x24}, new byte[] {0x49, 0x24, 0x92}, new byte[] {0x24, 0x92, 0x49}, 
                new byte[] {0x00, 0x00, 0x00}, new byte[] {0x11, 0x11, 0x11}, new byte[] {0x22, 0x22, 0x22}, new byte[] {0x33, 0x33, 0x33}, new byte[] {0x44, 0x44, 0x44}, 
                new byte[] {0x55, 0x55, 0x55}, new byte[] {0x66, 0x66, 0x66}, new byte[] {0x77, 0x77, 0x77}, new byte[] {0x88, 0x88, 0x88}, new byte[] {0x99, 0x99, 0x99}, 
                new byte[] {0xAA, 0xAA, 0xAA}, new byte[] {0xBB, 0xBB, 0xBB}, new byte[] {0xCC, 0xCC, 0xCC}, new byte[] {0xDD, 0xDD, 0xDD}, new byte[] {0xEE, 0xEE, 0xEE}, 
                new byte[] {0xFF, 0xFF, 0xFF}, new byte[] {0x92, 0x49, 0x24}, new byte[] {0x49, 0x24, 0x92}, new byte[] {0x24, 0x92, 0x49}, new byte[] {0x6D, 0xB6, 0xDB}, 
                new byte[] {0xB6, 0xDB, 0x6D}, new byte[] {0xDB, 0x6D, 0xB6} };

            ThreadSafeRandom.Shuffle<byte[]>(pattern);

            Random random = ThreadSafeRandom.Random;

            FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.None);

            for (int pass = 1; pass <= 35; ++pass)
            {
                for (int index = 0; index < 3; index++)
                {
                    fs.Position = 0;

                    for (long size = fs.Length; size > 0; size -= MAX_BUFFER_SIZE)
                    {
                        long bufferSize = (size < MAX_BUFFER_SIZE) ? size : MAX_BUFFER_SIZE;

                        byte[] buffer = new byte[bufferSize];

                        if (pass > 4 && pass < 32)
                        {
                            for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                            {
                                buffer[bufferIndex] = pattern[pass - 5][index];
                            }
                        }
                        else
                        {
                            for (int bufferIndex = 0; bufferIndex < bufferSize; ++bufferIndex)
                            {
                                buffer[bufferIndex] = (byte)(random.Next() % 256);
                            }
                        }

                        fs.Write(buffer, 0, buffer.Length);
                        fs.Flush(true);
                    }
                }
            }

            fs.Close(); fs.Dispose(); fs = null;
        }

        #endregion
    }
}