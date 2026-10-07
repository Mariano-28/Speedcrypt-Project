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

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PgpValidationResult: Represents the result of a PGP key path validation
    /// performed by the Speedcrypt PGP subsystem.
    /// </summary>
    ///
    /// <remarks>
    /// This enumeration defines the possible outcomes returned by PGP validation
    /// routines used within Speedcrypt.
    ///
    /// <summary>
    /// Created by Mariano Ortu
    /// PgpValidationResult: Enumerates possible outcomes of PGP key folder validation.
    /// </summary>
    ///
    /// <remarks>
    /// This enum provides strongly-typed results for PGP folder validation operations within the Speedcrypt framework:
    /// - Ok: Folder passes all checks
    /// - InvalidPath: Path is null, empty, or whitespace
    /// - MissingKeyFiles: One or both required PGP key files are missing
    /// - NotRegisteredInConfiguration: Folder is not found in the configuration registry
    /// - ConfigurationError: General failure in configuration validation
    ///
    /// Usage of this enum ensures clear and consistent handling of validation results
    /// throughout the Speedcrypt framework and facilitates meaningful logging and user messages.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public enum PgpValidationResult
    {
        Ok = 0,
        InvalidPath,
        MissingKeyFiles,
        NotRegisteredInConfiguration,
        ConfigurationError = 4
    }
}
