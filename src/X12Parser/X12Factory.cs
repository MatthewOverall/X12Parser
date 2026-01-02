using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace X12Parser
{
    public class X12Factory
    {
        private Dictionary<string, Type> _objects;
        private Dictionary<string, List<PropCache>> _properties;

        private readonly Type _type;

        public X12Factory(Type t) : this(t, Assembly.GetEntryAssembly())
        {
            //_type = t;
            //var externalAssembly = Assembly.GetEntryAssembly();
            //FindClasses(externalAssembly);
        }

        public X12Factory(Type t, Assembly externalAssembly)
        {
            _type = t;
            FindClasses(externalAssembly);
        }

        public void DumpProperties()
        {
            _properties.Dump();
        }

        public List<PropCache> GetPropertiesForType(string type)
        {
            if (_properties.ContainsKey(type)) return _properties[type];
            else return new List<PropCache>();
        }

        public void FindClasses(Assembly externalAssembly)
        {
            _properties = new Dictionary<string, List<PropCache>>();

            var internalAssembly = Assembly.GetExecutingAssembly();
            //var externalAssembly = Assembly.GetEntryAssembly();

            _objects = internalAssembly.GetTypes()
                .Where(x => x.BaseType == _type)
                .ToDictionary(x => x.Name, x => x);

            if (internalAssembly != externalAssembly && externalAssembly != null)
            {
                var external = externalAssembly.GetTypes()
                    .Where(x => /*x.BaseType == _type ||*/ x.IsSubclassOf(_type))
                    .ToDictionary(x => x.Name, x => x);

                foreach (var ex in external)
                {
                    //_objects.Add(ex.Key, ex.Value);
                    _objects[ex.Key] = ex.Value;
                }
            }
        }

        public X12 GetX12Item(string data, int index, bool dataChecks = true, bool boundsChecks = false, MessageSeparators separators = null)
        {
            //I would recommend removing this assumption and require the valid separators to be passed in.
            //* is the most common but not required, PIPE is the default repetition separator for 00501+ so this will likely break any 00501+ files.
            var dataElementSeparator = separators == null ? new[] { "*", "|" } : new[] { separators.DataElementSeparator };
            var segments = data.Split(dataElementSeparator, StringSplitOptions.None).ToList();
            var segment = segments.First();
            if (!_objects.ContainsKey(segment))
            {
                var generic = (X12)Activator.CreateInstance(typeof(X12));
                generic.RecordType = segment;
                generic.SegmentIndex = index;
#if INCLUDERAW
                generic.RawValue = data;
#endif
                return generic;
            }

            var type = _objects[segment];
            var obj = (X12)Activator.CreateInstance(type);
            obj.RecordType = segment;
            obj.SegmentIndex = index;
#if INCLUDERAW
            obj.RawValue = data;
#endif

            if (!_properties.ContainsKey(segment))
            {
                CacheProperties(segment, type);
            }

            var pc = _properties[segment];

            if (boundsChecks)
            {
                if (segments.Count > pc.Count) throw new FormatException($"Segment {segment} has {pc.Count} properties, but we have {segments.Count} values");
            }

            // blank out all optional properties, so we don't have nulls
            foreach (var p in pc.Where(x => x.Segment.Optional))
            {
                p.Property.SetValue(obj, "");
            }

            // now set them to the values we have
            for (var i = 1; i < segments.Count; i++)
            {
                //if (i > pc.Count) break;
                var prop = pc.FirstOrDefault(x => x.Segment.Order == i);
                if (prop == null) break;
                var value = segments[i];

                // Now, check what we've got, if we want to...
                if (dataChecks)
                {
                    CheckValue(value, prop.Segment, prop.Property);
                }

                prop.Property.SetValue(obj, value);
            }

            return obj;
        }

        public MessageSeparators GetMessageSeparatorsOrDefault(string text)
        {
            try
            {
                return GetMessageSeparators(text);
            }
            catch (Exception e)
            {
                return MessageSeparators.Default;
            }
        }

        public MessageSeparators GetMessageSeparators(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                throw new ArgumentException("EDI text is empty.");
            }

            // Remove UTF-8 BOM only
            text = text.TrimStart('\uFEFF');

            // 1) Find ISA (allow BOM/whitespace/newlines before it)
            int isaPos = text.IndexOf("ISA", StringComparison.Ordinal);
            if (isaPos < 0)
                throw new FormatException("ISA segment not found.");

            // 2) Element separator is the 4th character: ISA{sep}
            if (text.Length < isaPos + 4)
                throw new FormatException("Truncated ISA segment.");

            char elementSep = text[isaPos + 3];

            // 3) Walk ISA fields using fixed lengths (ISA01..ISA16)
            // lengths per X12: 2,10,2,10,2,15,2,15,6,4,1,5,9,1,1,1
            int[] lens = { 2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1 };

            int cursor = isaPos + 4; // after "ISA" + elementSep

            string isa11 = null;
            string isa12 = null;
            string isa16 = null;

            for (int i = 0; i < lens.Length; i++)
            {
                int len = lens[i];
                if (text.Length < cursor + len)
                    throw new FormatException("Truncated ISA segment while reading fixed-width elements.");

                string value = text.Substring(cursor, len);
                cursor += len;

                // Capture selected fields
                // i is 0-based: ISA11 is index 10, ISA12 is index 11, ISA16 is index 15
                if (i == 10) isa11 = value;
                if (i == 11) isa12 = value;
                if (i == 15) isa16 = value;

                // After each element except the last, there must be an element separator
                if (i < lens.Length - 1)
                {
                    if (text.Length <= cursor)
                        throw new FormatException("Truncated ISA segment (missing element separator).");

                    if (text[cursor] != elementSep)
                        throw new FormatException($"Invalid ISA format: expected element separator '{elementSep}' at position {cursor}.");

                    cursor++; // consume separator
                }
            }

            // 4) Segment terminator is the next char immediately after ISA16
            if (text.Length <= cursor)
                throw new FormatException("Truncated ISA segment (missing segment terminator).");

            char segmentTerminator = text[cursor];

            // ISA16 is 1 char: component element separator
            if (string.IsNullOrEmpty(isa16) || isa16.Length != 1)
                throw new FormatException("Invalid ISA16 (component element separator).");

            // 5) Repetition separator (ISA11) is meaningful for 00501+
            // ISA12 is fixed 5 chars like "00501"
            bool is00501OrHigher = false;
            if (!string.IsNullOrWhiteSpace(isa12))
            {
                // Safe comparison if it’s numeric-looking
                if (int.TryParse(isa12.Trim(), out var ver))
                    is00501OrHigher = ver >= 501;
            }


            var seps = new MessageSeparators
            {
                DataElementSeparator = elementSep.ToString(),
                ComponentElementSeparator = isa16,
                SegmentSeparator = segmentTerminator.ToString(),
                RepetitionSeparator = is00501OrHigher ? isa11 : null
            };

            return seps;
        }

        private void CacheProperties(string segment, Type type)
        {
            var props = type.GetProperties();
            var seenOrder = new Dictionary<int, string>();
            var previousOrder = -1;
            var maxKey = 0;

            var list = new List<PropCache>();
            foreach (var prop in props)
            {
                var custom = (Segment)prop.GetCustomAttribute(typeof(Segment));
                if (custom == null) continue; // throw new Exception($"Property {prop.Name} missing Segment Attribute");
                if (seenOrder.ContainsKey(custom.Order))
                    throw new ArgumentException($"Segment order {custom.Order} has already been used on property {seenOrder[custom.Order]}. Doubting that it is also for {prop.Name}, should this be {++previousOrder}?");
                if (seenOrder.Any())
                {
                    maxKey = seenOrder.Max(x => x.Key);
                }

                if (maxKey < custom.Order - 1) throw new ArgumentException($"Segment order {custom.Order} on property {prop.Name} was used before segment order {custom.Order - 1}, That doesn't seem correct.");
                seenOrder.Add(custom.Order, prop.Name);
                previousOrder = custom.Order;
                var propCache = new PropCache
                {
                    Segment = custom,
                    Property = prop
                };
                list.Add(propCache);
            }

            _properties.Add(segment, list);
        }

        private void CheckValue(string value, Segment seg, PropertyInfo prop)
        {
            if (seg.Optional && string.IsNullOrEmpty(value)) return;
            if (seg.MinLength.HasValue && seg.MaxLength.HasValue && seg.MaxLength < seg.MinLength)
                throw new ArgumentException($"Segment {prop.ReflectedType.Name}.{prop.Name} max length of {seg.MaxLength.Value} is less than min length of {seg.MinLength.Value}");
            if (seg.MinLength.HasValue && seg.MaxLength.HasValue && seg.MinLength > seg.MaxLength)
                throw new ArgumentException($"Segment {prop.ReflectedType.Name}.{prop.Name} min length of {seg.MinLength.Value} is greater than min length of {seg.MaxLength.Value}");
            if (seg.MinLength.HasValue && value.Length < seg.MinLength.Value) throw new ArgumentException($"Segment {prop.ReflectedType.Name}.{prop.Name} min length is defined as {seg.MinLength.Value} but length is {value.Length}");
            if (seg.MaxLength.HasValue && value.Length > seg.MaxLength.Value) throw new ArgumentException($"Segment {prop.ReflectedType.Name}.{prop.Name} max length is defined as {seg.MaxLength.Value} but length is {value.Length}");
        }
    }


    public class MessageSeparators
    {
        public static MessageSeparators Default { get; } = new MessageSeparators();
        public string SegmentSeparator { get; set; } = "~"; // e.g. "~"
        public string DataElementSeparator { get; set; } = "*"; // e.g. "*"
        public string ComponentElementSeparator { get; set; } = ">"; // e.g. ">"
        public string RepetitionSeparator { get; set; } = "|"; // e.g. "|" (00501+), optional
    }
}