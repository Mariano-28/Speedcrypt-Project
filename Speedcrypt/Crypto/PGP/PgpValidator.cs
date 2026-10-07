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

using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PgpValidator: Performs comprehensive validation of PGP key folders.
    /// </summary>
    ///
    /// <remarks>
    /// This sealed class provides structured validation for PGP key directories used in the Speedcrypt framework.
    /// It ensures that each folder:
    /// - Is not null, empty, or whitespace
    /// - Contains the required PGP key files (private and public)
    /// - Is registered in the configuration file (via PgpPathValidator)
    ///
    /// Validation results are returned as a strongly-typed <see cref="PgpValidationResult"/> enum:
    /// - Ok: Folder passes all checks
    /// - InvalidPath: Path is null, empty, or whitespace
    /// - MissingKeyFiles: One or both required PGP key files are missing
    /// - NotRegisteredInConfiguration: Folder is not found in the configuration registry
    /// - ConfigurationError: General failure in configuration validation
    ///
    /// This class also provides:
    /// - Human-readable messages for each validation result via <see cref="GetMessage(PgpValidationResult)"/>
    /// - Centralized logging of validation errors using <see cref="CentralLog.LogEvent"/>
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public sealed class PgpValidator
    {
        private readonly PgpPathValidator configValidator;

        public PgpValidator()
        {
            // Initialize configuration validator
            configValidator = new PgpPathValidator();
        }
        public PgpValidationResult Validate(string folderPath)
        {
            // Check for null or empty path
            if (string.IsNullOrWhiteSpace(folderPath))
            {
                LogValidationError("Invalid PGP key folder path. Operation aborted.");
                return PgpValidationResult.InvalidPath;
            }

            // Validate physical presence of required key files
            if (!KeyPathValidator.Validate(folderPath))
            {
                LogValidationError("Required PGP key files are missing. Operation aborted.");
                return PgpValidationResult.MissingKeyFiles;
            }

            // Validate registration in configuration file
            if (!configValidator.IsValid(folderPath))
            {
                LogValidationError("Required PGP key folder is not registered in configuration. Operation aborted.");
                return PgpValidationResult.NotRegisteredInConfiguration;
            }

            // All validations passed
            return PgpValidationResult.Ok;
        }
        public string GetMessage(PgpValidationResult result)
        {
            switch (result)
            {
                case PgpValidationResult.InvalidPath:
                    return "Invalid PGP key folder path. Operation aborted.";

                case PgpValidationResult.MissingKeyFiles:
                    return "Required PGP key files are missing. Operation aborted.";

                case PgpValidationResult.NotRegisteredInConfiguration:
                    return "Required PGP key folder is not registered in configuration. Operation aborted.";

                case PgpValidationResult.Ok:
                    return string.Empty;

                case PgpValidationResult.ConfigurationError:
                    return "PGP configuration validation failed. Operation aborted.";

                default:
                    return "Unknown PGP validation error. Operation aborted.";
            }
        }
        private void LogValidationError(string message)
        {
            CentralLog.LogEvent("PGP Validation", message, nameof(Validate),
                true);
        }
    }
}