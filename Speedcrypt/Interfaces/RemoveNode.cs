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

// Speedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// RemoveNode: Infrastructure support class responsible for
    /// controlled removal of parent nodes from the XML configuration
    /// within Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to safely remove configuration nodes
    /// when they are no longer associated with active child entries,
    /// enforcing project-level invariants and structural consistency.
    ///
    /// The removal logic is purely administrative and configuration-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///    
    /// Special constraint:
    /// Configuration nodes associated with PGP engines are explicitly protected
    /// and must never be removed by design.
    ///
    /// Designed for configuration integrity, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public class RemoveNode
    {
        private readonly PrivateXmlConfig _xml;
        public RemoveNode(PrivateXmlConfig xml)
        {
            _xml = xml;
        }
        public void Execute(string parentKey)
        {
            if (string.IsNullOrEmpty(parentKey))
                return;

            if (!_xml.ContainsKey(parentKey))
                return;

            string parentValue = _xml.GetValue(parentKey);
            if (string.IsNullOrEmpty(parentValue))
                return;

            // Engine identifier is stored in parts[2] of the parent value
            string[] parts = parentValue.Split('|');
            if (parts.Length < 3)
                return;

            // PGP must NEVER be removed
            if (parts[2].IndexOf("PGP", StringComparison.OrdinalIgnoreCase) >= 0)
                return;

            // Check children
            var children = _xml.GetChildNodes(parentKey);

            if (children == null || children.Count == 0)
            {
                _xml.RemoveKey(parentKey);
            }
        }
    }
}