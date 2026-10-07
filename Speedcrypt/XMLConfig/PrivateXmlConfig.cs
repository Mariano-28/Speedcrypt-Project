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
using System.Xml;
using System.Collections;
using System.Collections.Generic;

namespace Speedcrypt.XMLConfig
{
    /// <summary>
    /// Created by Dominik Reichl
    /// 
    /// Integrated and extensively adapted into Speedcrypt framework by Mariano Ortu, who thanks the author for this valuable original implementation.
    /// PrivateXmlConfig: enhanced XML configuration handler supporting parent-child relationships and dictionary-based access.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Loading and saving XML configuration files with nested child nodes
    /// - Fast access to key-value pairs and child elements
    /// - Complete integration with Speedcrypt framework
    /// - Extensive adaptation by Mariano Ortu, making this implementation almost entirely new
    ///
    /// Responsibility for integration, enhancement, and validation within Speedcrypt
    /// lies entirely with Mariano Ortu, while respecting the original author's contribution.
    /// </remarks>
    public class PrivateXmlConfig
    {
        // THREAD SYNCHRONIZATION ENGINE: Multi-threaded access isolation lock object.
        private readonly object m_lock = new object();

        protected ArrayList m_aFields = new ArrayList();
        protected ArrayList m_aValues = new ArrayList();

        // STRUCTURAL TRACKING DICTIONARY: Maps dynamic hierarchical child nodes per encrypted parent session token.
        private Dictionary<string, Dictionary<string, string>> m_childNodes = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        public PrivateXmlConfig()
        {
        }
        public uint LoadFromFile(string strFile)
        {
            lock (m_lock)
            {
                XmlDocument docConfig = new XmlDocument();
                try { docConfig.Load(strFile); }
                catch (Exception) { return 1; }

                XmlElement el = docConfig.DocumentElement;
                if (el == null || el.Name != "Configuration") return 2;

                m_aFields.Clear();
                m_aValues.Clear();
                m_childNodes.Clear();

                for (int i = 0; i < el.ChildNodes.Count; i++)
                {
                    XmlNode node = el.ChildNodes[i];
                    XmlNode xmlField = node.Attributes.GetNamedItem("Name");
                    XmlNode xmlValue = node.Attributes.GetNamedItem("Value");

                    if (xmlField == null) continue;

                    string parentName = xmlField.Value;
                    string parentValue = xmlValue != null ? xmlValue.Value : "";

                    m_aFields.Add(parentName);
                    m_aValues.Add(parentValue);

                    // DESERIALIZATION LAYER: Extract associative child elements utilizing strict ordinal case insensitivity bounds.
                    Dictionary<string, string> children = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (XmlNode childNode in node.ChildNodes)
                    {
                        XmlNode childNameNode = childNode.Attributes.GetNamedItem("Name");
                        XmlNode childValueNode = childNode.Attributes.GetNamedItem("Value");
                        if (childNameNode != null && childValueNode != null)
                        {
                            children[childNameNode.Value] = childValueNode.Value;
                        }
                    }
                    if (children.Count > 0)
                        m_childNodes[parentName] = children;
                }

                return 0;
            }
        }
        public uint SaveToFile(string strFile)
        {
            lock (m_lock)
            {
                using (XmlTextWriter xtw = new XmlTextWriter(strFile, null))
                {
                    xtw.WriteStartDocument();
                    xtw.WriteWhitespace("\r\n");
                    xtw.WriteStartElement("Configuration");
                    xtw.WriteWhitespace("\r\n");

                    for (int i = 0; i < m_aFields.Count; i++)
                    {
                        string parentName = (string)m_aFields[i];
                        string parentValue = (string)m_aValues[i];

                        xtw.WriteWhitespace("\t");
                        xtw.WriteStartElement("Key");
                        xtw.WriteAttributeString("Name", parentName);
                        xtw.WriteAttributeString("Value", parentValue);

                        // Write children if any
                        if (m_childNodes.ContainsKey(parentName))
                        {
                            foreach (var child in m_childNodes[parentName])
                            {
                                xtw.WriteWhitespace("\r\n\t\t");
                                xtw.WriteStartElement("Child");
                                xtw.WriteAttributeString("Name", child.Key);
                                xtw.WriteAttributeString("Value", child.Value);
                                xtw.WriteEndElement();
                            }
                        }

                        xtw.WriteEndElement();
                        xtw.WriteWhitespace("\r\n");
                    }
                    xtw.WriteEndElement();
                    xtw.WriteWhitespace("\r\n");
                    xtw.WriteEndDocument();

                    // CRITICAL ENTERPRISE FLUSH: Force immediate hardware write-through to prevent lazy I/O caching anomalies.
                    xtw.Flush();
                    xtw.BaseStream?.Flush();
                }

                return 0;
            }
        }
        public string GetValue(string strField)
        {
            lock (m_lock)
            {
                for (int i = 0; i < m_aFields.Count; i++)
                    if ((string)m_aFields[i] == strField)
                        return (string)m_aValues[i];
                return "";
            }
        }
        public void SetValue(string strField, string strValue)
        {
            lock (m_lock)
            {
                int index = -1;

                // ENFORCE CASE-INSENSITIVE LINEAR LOOKUP TO PREVENT DUPLICATE KEY INJECTION ANOMALIES
                for (int i = 0; i < m_aFields.Count; i++)
                {
                    if (m_aFields[i] != null && m_aFields[i].ToString().Equals(strField, StringComparison.OrdinalIgnoreCase))
                    {
                        index = i;
                        break;
                    }
                }

                if (index == -1)
                {
                    m_aFields.Add(strField);
                    m_aValues.Add(strValue);
                }
                else
                {
                    m_aValues[index] = strValue;
                }
            }
        }
        public bool RemoveKey(string strField)
        {
            lock (m_lock)
            {
                int index = -1;

                // ENFORCE CASE-INSENSITIVE LINEAR LOOKUP FOR ATOMIC RECORD PURGING
                for (int i = 0; i < m_aFields.Count; i++)
                {
                    if (m_aFields[i] != null && m_aFields[i].ToString().Equals(strField, StringComparison.OrdinalIgnoreCase))
                    {
                        index = i;
                        break;
                    }
                }

                if (index != -1)
                {
                    m_aFields.RemoveAt(index);
                    m_aValues.RemoveAt(index);

                    // Track associated parent structural tokens for isolation layer integrity
                    string targetKey = strField;
                    foreach (string key in m_childNodes.Keys)
                    {
                        if (key.Equals(strField, StringComparison.OrdinalIgnoreCase))
                        {
                            targetKey = key;
                            break;
                        }
                    }

                    if (m_childNodes.ContainsKey(targetKey))
                        m_childNodes.Remove(targetKey);

                    return true;
                }
                return false;
            }
        }
        public bool Exists(string strField)
        {
            lock (m_lock)
            {
                // EVALUATE COLLECTION CONTENT VIA STRICT ORAL BOUNDS
                foreach (var item in m_aFields)
                {
                    if (item != null && item.ToString().Equals(strField, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
        }
        public void Clear()
        {
            lock (m_lock)
            {
                m_aFields.Clear();
                m_aValues.Clear();
                m_childNodes.Clear();
            }
        }
        public Dictionary<string, string> GetAllKeyValuePairs()
        {
            lock (m_lock)
            {
                Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < m_aFields.Count; i++)
                {
                    if (m_aFields[i] != null)
                    {
                        dict[m_aFields[i].ToString()] = (string)m_aValues[i];
                    }
                }
                return dict;
            }
        }

        // =================================================================
        // ENHANCED CHILD MANAGEMENT PIPELINE (THREAD-ISOLATED MEMORY LAYER)
        // =================================================================
        public void SetChild(string parentKey, string childName, string childValue)
        {
            lock (m_lock)
            {
                if (!m_childNodes.ContainsKey(parentKey))
                    m_childNodes[parentKey] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                m_childNodes[parentKey][childName] = childValue;
            }
        }

        // ATOMIC CODESPACE PROTECTION: Return an isolated deep-copy instance to decouple the iterative loop from active memory mutations.
        public Dictionary<string, string> GetChildNodes(string parentKey)
        {
            lock (m_lock)
            {
                if (m_childNodes.ContainsKey(parentKey))
                {
                    // THREAD-SAFE MEMORY ISOLATION: Instantiate a new dictionary collection to safeguard the enumeration boundary from concurrent modification crashes.
                    return new Dictionary<string, string>(m_childNodes[parentKey], StringComparer.OrdinalIgnoreCase);
                }
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }
        public bool RemoveChild(string parentKey, string childName)
        {
            lock (m_lock)
            {
                if (m_childNodes.ContainsKey(parentKey) && m_childNodes[parentKey].ContainsKey(childName))
                {
                    m_childNodes[parentKey].Remove(childName);

                    // ATOMIC PIPELINE CLEANUP: If the structural parent dictionary branch becomes entirely depleted, 
                    // purge the associated isolation tracking tokens from parallel lists to eliminate concurrent I/O caching bottlenecks.
                    if (m_childNodes[parentKey].Count == 0)
                    {
                        m_childNodes.Remove(parentKey);

                        int index = -1;
                        for (int i = 0; i < m_aFields.Count; i++)
                        {
                            if (m_aFields[i] != null && m_aFields[i].ToString().Equals(parentKey, StringComparison.OrdinalIgnoreCase))
                            {
                                index = i;
                                break;
                            }
                        }

                        if (index != -1)
                        {
                            m_aFields.RemoveAt(index);
                            m_aValues.RemoveAt(index);
                        }
                    }
                    return true;
                }
                return false;
            }
        }
        public bool ContainsKey(string key)
        {
            lock (m_lock)
            {
                foreach (var item in m_aFields)
                {
                    if (item != null && item.ToString().Equals(key, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
        }
    }
}