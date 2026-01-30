# JSON+ Protocol Dissector
# ========================

## Overview

The JSON+ dissector extends Wireshark's standard JSON dissector with
dictionary-driven field parsing. It provides dynamic field registration
based on your protocol specifications using XML dictionary files.

## Files in This Directory

- **config.txt**: Controls which dictionary files to load
- **jsonmain.xml**: Dictionary with example fields
- **DICTIONARY-GUIDE.txt**: Complete guide to creating dictionary files
- **example-api.xml**: Example of additional dictionary (commented out)
- **parsers/**: Directory for external parser scripts

## Configuration

Edit `config.txt` to control which dictionaries are loaded:

# Active - will be loaded
jsonmain.xml

# Commented out - will NOT be loaded
# example-api.xml

Only fields from active dictionary files will be registered in Wireshark.

## Enabling JSON+

JSON+ mode must be enabled in Wireshark preferences:
- GUI: Edit → Preferences → Protocols → JSON → "Display JSON in JSON+ form"
- tshark: Use `-o "json.plus_form:TRUE"`

## Creating Your Own Dictionary

1. **Copy jsonmain.xml** as a template:
   cp jsonmain.xml my-protocol.xml

2. **Edit my-protocol.xml** to define your JSON fields:
   <field name="user_id" path="user.id" type="Integer"/>
   <field name="username" path="user.name" type="String"/>

3. **Add to config.txt**:
   jsonmain.xml
   my-protocol.xml

4. **Restart Wireshark/tshark** to load new fields

See **DICTIONARY-GUIDE.txt** for complete instructions.

## Usage Examples

### Capture and Dissect:
# Capture traffic
tcpdump -i lo port 9999 -w capture.pcap

# Dissect with JSON+
./run/tshark -r capture.pcap -o "json.plus_form:TRUE" -V

### Filter by Field:
# Filter by integer field
./run/tshark -r capture.pcap -o "json.plus_form:TRUE" -Y "json.user.id == 42"

# Filter by string field
./run/tshark -r capture.pcap -o "json.plus_form:TRUE" -Y 'json.user.name == "John"'

# Filter by float field
./run/tshark -r capture.pcap -o "json.plus_form:TRUE" -Y "json.price > 100.0"

# Filter by boolean field
./run/tshark -r capture.pcap -o "json.plus_form:TRUE" -Y "json.active == 1"

### List All Fields:
# See all registered json fields
./tshark -o "json.plus_form:TRUE" -G fields 2>/dev/null | grep "^F" | grep "json\."

### Check Dictionary Loading:
# Verify dictionary fields are registered
./tshark -o "json.plus_form:TRUE" -G fields 2>/dev/null | grep "json\." | wc -l

## Field Naming Convention

Dictionary path → Filter field name:
- `path="user.id"` → Filter: `json.user.id`
- `path="items[].price"` → Filter: `json.items.price`
- `path="request_id"` → Filter: `json.request_id`

All filter fields use the `json.` prefix followed by the path (with array brackets removed).

## Hierarchical Display

Array elements are displayed hierarchically:

JSON+ form:
  items: []
    0: {...}
      id: 1
      name: Widget
      price: 19.99
    1: {...}
      id: 2
      name: Gadget
      price: 29.99

Each array element can be expanded individually.

## Supported Data Types

### Basic Types

- **String**: Text values (FT_STRING)
- **Integer**: 64-bit integers (FT_INT64)
- **Float**: Floating point numbers (FT_DOUBLE)
- **Boolean**: True/false values (FT_BOOLEAN)
- **Object**: Nested objects (container type)
- **Array**: Arrays of any type (container type)

### Special Display Types

You can create custom types with specialized display formats using the `display` attribute:

<!-- Define custom types with special display formatting -->
<typedefn type-name="IPAddress" base-type="string" display="ipv4"/>
<typedefn type-name="MacAddress" base-type="string" display="ether"/>
<typedefn type-name="Timestamp" base-type="int64" display="absolute_time"/>
<typedefn type-name="Hex2Dec" base-type="string" display="hex2dec"/>

<!-- Use in fields -->
<field name="ClientIP" path="client.ip" type="IPAddress"/>
<field name="ServerMAC" path="server.mac" type="MacAddress"/>
<field name="EventTime" path="event.timestamp" type="Timestamp"/>
<field name="CellId" path="cell.id" type="Hex2Dec"/>

**Available display formats:**
- **ipv4**: IPv4 addresses (dotted decimal notation)
- **ipv6**: IPv6 addresses (colon-separated hex)
- **ether**: MAC/Ethernet addresses (colon-separated hex)
- **absolute_time**: Unix timestamps (displayed as date/time)
- **relative_time**: Relative time in seconds (displayed as duration)
- **hex2dec**: Hex strings displayed as decimal with compact hex (e.g., "2328" → 9000 (0x2328))

**Benefits:**
- Proper formatting in packet tree
- Wireshark's native IP/MAC address filtering
- Human-readable timestamps
- Numeric filtering and sorting for hex values
- Support for enum values on hex2dec fields
- Validation and error checking



## Info Column Labels

Add custom labels to the Info column:

<field name="PreemptCap" path="qos.preemptCap" type="String" info="preempt"/>

This adds "preempt: value" to the Info column for quick identification.

## Enum Values

Define enums for integer fields:

<field name="Priority" path="priority" type="Integer">
    <enum name="high" code="1"/>
    <enum name="medium" code="2"/>
    <enum name="low" code="3"/>
</field>

Displays as: "Priority: high (1)"

Enums also work with hex2dec fields (values must fit in 32-bit range):

<typedefn type-name="Hex2Dec" base-type="string" display="hex2dec"/>
<field name="CellType" path="cell.type" type="Hex2Dec">
    <enum name="LTE" code="1"/>
    <enum name="5G_NR" code="2"/>
    <enum name="UMTS" code="3"/>
</field>

For JSON value "2", displays as: "CellType: 5G_NR (2, 0x2)"

**Note:** Enum values with hex2dec must be ≤ 4294967295 (32-bit limit).
For larger hex values without enums, use hex2dec without enum definitions.

## Common Use Cases

### 1. REST API Monitoring
Define fields for your API endpoints:
- Request/response IDs
- Status codes
- Timestamps
- User IDs
- Resource identifiers

### 2. Custom Protocol Analysis
Create dictionaries for proprietary JSON protocols:
- IoT device messages
- Game server communication
- Microservice APIs
- Real-time data feeds

### 3. Multiple Protocols
Load multiple dictionaries for different protocols:
- One dictionary per API version
- One dictionary per service
- Separate dictionaries for different message types

### 4. Selective Field Loading
Comment out dictionaries to reduce registered fields:
- Load only what you need for current analysis
- Faster Wireshark startup
- Cleaner field list

## Troubleshooting

**Problem: Fields not appearing in packet details**
- Check JSON+ is enabled: `-o "json.plus_form:TRUE"`
- Check that dictionary is listed in config.txt (not commented)
- Verify XML syntax is valid
- Verify field paths match your JSON structure

**Problem: Cannot filter by field**
- Verify field is registered: `tshark -o "json.plus_form:TRUE" -G fields | grep json.field`
- String values need quotes: `json.name == "value"`

**Problem: Type mismatch errors**
- Verify JSON data type matches dictionary type
- Numbers in JSON strings won't match Integer type

**Problem: Array fields not working**
- Check path uses brackets: `items[].id` not `items.id`
- Verify full path from root: `response.items[].id`

**Problem: Nested objects not dissecting**
- Verify full path in dictionary: `user.profile.email` not `email`
- Check parent object is defined with type="Object"

## Performance Tips

1. **Use selective loading**: Only load dictionaries you need
2. **Specific filters**: Use specific field filters instead of generic ones
3. **Minimal fields**: Don't define fields you won't use
4. **Protocol names**: Define protocol names/ports for automatic detection

## Advanced Topics

### Multiple API Versions
api-v1.xml
api-v2.xml
api-v3.xml
Load only the version you're analyzing.

### Protocol Detection
Use port numbers and display names in dictionary:
<protocol name="My API" port="9999" transport="tcp" displayName="MyAPI"/>

The displayName will appear in the Protocol column when JSON+ is enabled.

### Custom Field Names
Display names can differ from paths:
<field name="User Identifier" path="user.id" type="Integer"/>
Display shows "User Identifier", filter uses `json.user.id`

### Special Formatting for Network Data
Use display types for network-related fields:
<!-- Type definitions -->
<typedefn type-name="IPAddress" base-type="string" display="ipv4"/>
<typedefn type-name="MacAddress" base-type="string" display="ether"/>
<typedefn type-name="Timestamp" base-type="int64" display="absolute_time"/>

<!-- Fields using special types -->
<field name="SourceIP" path="source.ip" type="IPAddress"/>
<field name="DestIP" path="dest.ip" type="IPAddress"/>
<field name="ClientMAC" path="client.mac" type="MacAddress"/>
<field name="EventTime" path="event.time" type="Timestamp"/>

This enables:
- IP address filtering with CIDR notation: `json.source.ip in {192.168.1.0/24}`
- Timestamp display as readable dates
- MAC address proper formatting

### Custom Display Filters (df attribute)
For complex protocols with long field names, use custom filter abbreviations:
<field name="Nfconsumeridentification" path="nfConsumerIdentification" type="Object" df="nfci">
    <field name="Nfipv4Address" path="nfConsumerIdentification.nFIPv4Address" type="IPAddress" df="nfci.ipv4"/>
    <field name="Nfname" path="nfConsumerIdentification.nFName" type="String" df="nfci.name"/>
</field>

Now filter with short names:
- `json.nfci.ipv4 == "10.0.1.1"` (instead of long path)
- `json.nfci.name contains "amf"`

### Complex Nesting
<field name="response" path="response" type="Object">
  <field name="data" path="response.data" type="Object">
    <field name="users" path="response.data.users" type="Array">
      <array-element type="Object">
        <field name="id" path="response.data.users[].id" type="Integer"/>
      </array-element>
    </field>
  </field>
</field>
Filter: `json.response.data.users.id`

## Resources

- **DICTIONARY-GUIDE.txt**: Complete dictionary file reference
- **config.txt**: Configuration file with inline help
- **jsonmain.xml**: Example dictionary file
- **example-api.xml**: Additional example (commented in config.txt)


Protocol Name: JSON (with JSON+ extension)
Filter Prefix: json
Dictionary Format: XML
Config File: config.txt (in resources/protocols/json/)
Dictionary Directory: resources/protocols/json/

## Authors

See AUTHORS file

Mark Stout <mark.stout@markstout.com>
