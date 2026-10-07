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
using System.Linq;
using System.Text;
using System.Security;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

/// <summary>
/// Created by Mariano Ortu
/// 
/// AntiTamperProtection: Runtime protection component for detecting tampering,
/// debugging, profiling, and integrity violations in critical application files.
/// </summary>
///
/// <remarks>
/// This class is part of the Speedcrypt project and belongs to the "Protect" module.
///
/// Purpose:
/// - Detect the presence of debuggers, profilers, and remote debugging sessions.
/// - Verify the integrity of critical application files using cryptographic hashes.
/// - Detect suspicious analysis or reverse-engineering tools running on the system.
/// - React to violations by optionally wiping sensitive material from memory.
/// - Provide a thread-safe internal log of detected violations.
///
/// Security scope and limits:
/// - This class implements all reasonable and effective protections achievable
///   in a managed .NET environment without kernel-level components.
/// - It is designed to raise the cost of analysis, tampering, and live inspection,
///   not to claim absolute or unbreakable protection.
/// - No software-based protection is insuperable; this component does everything
///   it can do within realistic technical boundaries.
///
/// Important:
/// - This class does not claim to defeat kernel debuggers, hypervisors,
///   or fully privileged attackers.
/// - Its role is defensive, deterrent, and damage-limiting, not absolute prevention.
///
/// Responsibility for algorithm choice, parameterization, integration,
/// and overall security validation lies entirely with the author.
/// </remarks>
public sealed class AntiTamperProtection
{
    private readonly byte[][] _criticalFileHashes;
    private readonly string[] _criticalFilePaths;
    private readonly bool _wipeOnViolation;
    private readonly StringBuilder _violationLog = new StringBuilder();
    private readonly object _logLock = new object();
    public AntiTamperProtection(string[] criticalFilePaths, byte[][] criticalFileHashes, bool wipeOnViolation = true)
    {
        if (criticalFilePaths == null || criticalFileHashes == null)
            throw new ArgumentNullException("Critical paths and hashes cannot be null.");

        if (criticalFilePaths.Length != criticalFileHashes.Length)
            throw new ArgumentException("Paths and hashes length mismatch.");

        if (criticalFilePaths.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Invalid file path detected.");

        _criticalFilePaths = criticalFilePaths;
        _criticalFileHashes = criticalFileHashes;
        _wipeOnViolation = wipeOnViolation;
    }
    public bool Validate(byte[] masterKeyBuffer = null, SecureString passwordBuffer = null)
    {
        try
        {
            if (IsDebuggingDetected())
            {
                RegisterViolation("Debugger or profiler detected.");
                WipeSensitive(masterKeyBuffer, passwordBuffer);
                return false;
            }

            if (!CheckFilesIntegrity())
            {
                RegisterViolation("Critical file integrity violation.");
                WipeSensitive(masterKeyBuffer, passwordBuffer);
                return false;
            }

            if (DetectSuspiciousProcesses())
            {
                RegisterViolation("Suspicious process detected.");
                WipeSensitive(masterKeyBuffer, passwordBuffer);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            RegisterViolation("Fatal exception: " + ex.Message);
            WipeSensitive(masterKeyBuffer, passwordBuffer);
            return false;
        }
    }

    // ----------------- Anti Debug -----------------
    private bool IsDebuggingDetected()
    {
        try
        {
            if (Debugger.IsAttached || IsDebuggerPresent())
                return true;

            bool isRemoteDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isRemoteDebuggerPresent);
            if (isRemoteDebuggerPresent)
                return true;

            string profiling = Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING");
            if (!string.IsNullOrEmpty(profiling) && profiling != "0")
                return true;
        }
        catch { }

        return false;
    }

    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    // ----------------- File Integrity -----------------
    private bool CheckFilesIntegrity()
    {
        for (int i = 0; i < _criticalFilePaths.Length; i++)
        {
            string path = _criticalFilePaths[i];
            byte[] expectedHash = _criticalFileHashes[i];

            if (!File.Exists(path))
            {
                RegisterViolation("Missing critical file: " + path);
                return false;
            }

            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] currentHash = sha.ComputeHash(fs);
                    if (!currentHash.SequenceEqual(expectedHash))
                    {
                        RegisterViolation("Hash mismatch: " + path);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                RegisterViolation("File integrity error: " + ex.Message);
                return false;
            }
        }

        return true;
    }

    // ----------------- Process Detection -----------------
    private bool DetectSuspiciousProcesses()
    {
        string[] suspicious =
        {
            "ollydbg",
            "ida",
            "x64dbg",
            "cheatengine",
            "wireshark",
            "dnspy"
        };

        try
        {
            foreach (Process proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (suspicious.Any(s => name.Contains(s)))
                        return true;

                    string module = null;
                    try { module = proc.MainModule.FileName.ToLowerInvariant(); }
                    catch (Exception ex)
                    {
                        RegisterViolation("Unable to access module: " + proc.ProcessName + " - " + ex.Message);
                    }
                    if (module != null && suspicious.Any(s => module.Contains(s)))
                        return true;
                }
                catch { }
            }
        }
        catch { }

        return false;
    }

    // ----------------- Wipe -----------------
    private void WipeSensitive(byte[] masterKeyBuffer, SecureString passwordBuffer)
    {
        if (!_wipeOnViolation)
            return;

        if (masterKeyBuffer != null)
            RtlZeroMemory(masterKeyBuffer, masterKeyBuffer.Length);

        passwordBuffer?.Clear();

        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    [DllImport("kernel32.dll")]
    private static extern void RtlZeroMemory(byte[] dst, int length);

    // ----------------- Logging -----------------
    private void RegisterViolation(string message)
    {
        lock (_logLock)
        {
            _violationLog.AppendLine(
                DateTime.UtcNow.ToString("O") + " - " + message);
        }
    }
    public string GetViolationLog()
    {
        lock (_logLock)
        {
            return _violationLog.ToString();
        }
    }
}