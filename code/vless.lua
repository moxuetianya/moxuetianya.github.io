--  -*- coding: utf-8 -*- 

-- 创建一个新的协议: 协议名称为 VLESS，在Packet Details窗格显示为 Vless Protocol
local vless_protoc = Proto("VLESS", "Vless Protocol")

local f_version = ProtoField.uint8("vless_proto.version", "Version", base.DEC)
local f_uuid = ProtoField.bytes("vless_proto.uuid", "UUID", base.none)
local f_extra_len = ProtoField.uint8("vless_proto.extra_len", "Extra length", base.DEC)
local f_extra = ProtoField.bytes("vless_proto.extra", "Extra", base.DASH)
local f_instruct = ProtoField.uint8("vless_proto.instruct", "Instruct", base.HEX)
local f_port = ProtoField.uint16("vless_proto.port", "Port", base.DEC)
local f_addr_type = ProtoField.uint8("vless_proto.addr_type", "Address Type", base.HEX)
local f_addr_ipv4 = ProtoField.ipv4("vless_proto.addr_ipv4", "Address Ipv4")
local f_addr_name = ProtoField.bytes("vless_proto.addr", "Address", base.DASH)
local f_addr_ipv6 = ProtoField.ipv6("vless_proto.addr_ipv6", "Address Ipv6")
local f_payload = ProtoField.string("vless_proto.payload", "Payload", base.ASCII)
-- 将字段添加到协议中
vless_protoc.fields = { f_version, f_uuid, f_uuid2, f_extra_len, f_extra, f_instruct, f_port, f_addr_type, f_addr_ipv4, f_addr_name, f_addr_ipv6 , f_payload } 
local data_dis = Dissector.get("data")

-- 定义协议的解析函数
function FUZZ_dissector(buffer, pinfo, tree)
    local length = buffer:len()
    -- 确保报文有足够的长度供解析
    if length < 26 then
        return false
    end

    local t_version = buffer(0, 1):uint()
    if t_version ~= 0 then
        return false
    end
    -- 显示协议名称 --在主窗口的 Protocol 字段显示的名称为 XX_Protobuf
    pinfo.cols.protocol = "VLESS"
    local t_uuid = buffer(1, 16)
    local t_extra_len = buffer(17, 1):uint()
    local t_extra = buffer(18, t_extra_len):bytes()

    local t_instruct = buffer(18 + t_extra_len, 1):uint()
    local t_port = buffer(19 + t_extra_len, 2):uint()
    local t_addr_type = buffer(21 + t_extra_len, 1):uint()
    local t_addr_len = 4
    if t_addr_type == 0x01 then
        -- IPv4
        -- pinfo.cols.info = "IPv4 Address"
    elseif t_addr_type == 0x04 then
        -- IPv6
        -- pinfo.cols.info = "IPv6 Address"
        t_addr_len = 4*4
    elseif t_addr_type == 0x03 then
        -- Domain Name
        -- pinfo.cols.info = "Domain Name"
        local domain_len = buffer(22 + t_extra_len, 1):uint8()
        t_addr_len = domain_len + 1 -- +1 for the length byte itself
    end
    local t_payload = buffer(22 + t_extra_len + t_addr_len):bytes()

    -- 在树形结构中添加Headers
    local subtree = tree:add(vless_protoc, buffer(0, 22+t_extra_len+t_addr_len), "Vless Header")
    -- 解析协议字段并添加到树中
    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_uuid, buffer(1, 16))
    subtree:add(f_extra_len, buffer(17, 1))
    if t_extra_len > 0 then
        -- 如果 extra_len 大于0，添加 extra 字段
        subtree:add(f_extra, buffer(18, t_extra_len))
    end
    subtree:add(f_instruct, buffer(18 + t_extra_len, 1))
    subtree:add(f_port, buffer(19 + t_extra_len, 2))
    subtree:add(f_addr_type, buffer(21 + t_extra_len, 1))
    if t_addr_type == 0x01 then
        subtree:add(f_addr_ipv4, buffer(22 + t_extra_len, 4))
    elseif t_addr_type == 0x04 then
        subtree:add(f_addr_ipv6, buffer(22 + t_extra_len, 16))
    elseif t_addr_type == 0x03 then
        local domain_len = buffer(22 + t_extra_len, 1):uint8()
        subtree:add(f_addr_name, buffer(22 + t_extra_len, domain_len + 1))
    end
    -- subtree:add(f_payload, buffer(22 + t_extra_len + t_addr_len))
    local raw_data = buffer(22 + t_extra_len + t_addr_len)
    Dissector.get("http"):call(raw_data:tvb(), pinfo, tree)
    pinfo.cols.protocol:append("-vreq")
    return true
end

function FUZZresp_dissector(buffer, pinfo, tree)
    local length = buffer:len()
    -- 确保报文有足够的长度供解析
    if length < 2 then
        return false
    end
    local t_extra_len = buffer(1, 1):uint()
    local subtree = tree:add(vless_protoc, buffer(0, 2+t_extra_len), "Vless Header")
    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_extra_len, buffer(1, 1))
    if t_extra_len > 0 then
        -- 如果 extra_len 大于0，添加 extra 字段
        subtree:add(f_extra, buffer(2, t_extra_len))
    end
    pinfo.cols.protocol = "VLESS"
    -- subtree:add(f_payload, buffer(2 + t_extra_len))
    local raw_data = buffer(2 + t_extra_len)
    Dissector.get("http"):call(raw_data:tvb(), pinfo, tree)
    pinfo.cols.protocol:append("-vrsp")
    return true
end

function vless_protoc.dissector(buffer, pinfo, tree)
    if buffer(0,2):uint() ~= 0 then
        if FUZZ_dissector(buffer, pinfo, tree) then
            -- valid Fuzz diagram
        else
            -- data这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用data
            data_dis:call(buffer, pinfo, tree)
        end
    else
        if FUZZresp_dissector(buffer, pinfo, tree) then
            -- valid Fuzz diagram
        else
            -- data这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用data
            data_dis:call(buffer, pinfo, tree)
        end
    end
end
-- 注册 dissector 到对应的 DLT_USER3 (150)
-- local wtap_encap_table = DissectorTable.get("wtap_encap")
-- wtap_encap_table:add(150, vless_protoc)
local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(50000, vless_protoc)

-- sudo cp ./vless.lua /usr/share/wireshark/vless.lua