#!/usr/bin/env lua
--[[ 
	A helper for parsing ip monitor result.
	If it find usable information, it store information by ubus plugin
	
	usage:
	ip monitor neigh | ip_mon_handler.lua
	
	test and debug:
	echo information | ip_mon_handler.lua
--]]

-- Compatibility: Lua-5.1
function split(str, pat)
	local t = {}  -- NOTE: use {n = 0} in Lua-5.0
	local fpat = "(.-)" .. pat
	local last_end = 1
	local s, e, cap = str:find(fpat, 1)
	while s do
		if s ~= 1 or cap ~= "" then
			table.insert(t,cap)
		end
		last_end = e+1
		s, e, cap = str:find(fpat, last_end)
	end
	if last_end <= #str then
		cap = str:sub(last_end)
		table.insert(t, cap)
	end
	return t
end

function debug_log(msg)
	local fh = io.open('/dev/console', 'w')
	if fh == nil then
		return
	end
	
	fh:write(msg .. "\n")
	fh:close()
end

function is_ip_address(ip_addr)
	if ip_addr == nil then
		return false
	end

	-- check format
	local pattern = '^(%d+)' .. string.rep('.(%d+)', 3) .. '$'
	local s, e, ip1, ip2, ip3, ip4 = string.find(ip_addr, pattern)
	if s == nil then
		return false
	end
	
	-- check address value
	local items = {ip1, ip2, ip3, ip4}
	for k, v in ipairs(items) do
		local value = tonumber(v)
		if value == nil then
			return false
		end
		
		if (value < 0) or (value) > 255 then
			return false
		end
	end
	
	return true
end

function ipv6_add_str_2_bin(ipv6_addr)
	if ipv6_addr == nil then
		return nil
	end

	local l1 = split(ipv6_addr, '::')
	if table.getn(l1) <= 0 or table.getn(l1) > 2 then
		return nil
	end

	local l2_first_half = split(l1[1], ':')
	local segment = table.getn(l2_first_half)
	if table.getn(l1) == 1 and segment ~= 8 then
		return nil
	end
	
	local l2_second_half
	if table.getn(l1) == 2 then
		l2_second_half = split(l1[2], ':')
		segment = segment + table.getn(l2_second_half)
	end
	
	if segment > 8 then
		return nil
	end
	
	local ipv6_addr_bin = {0, 0, 0, 0, 0, 0, 0, 0}
	
	for k, v in ipairs(l2_first_half) do
		if string.find(v, '^%x+') == nil then
			return nil
		end
		
		ipv6_addr_bin[k] = tonumber(v, 16)
		if ipv6_addr_bin[k] > 0xffff then
			return nil
		end
	end	
	
	if l2_second_half ~= nil then
		local idx_offset = 8 - table.getn(l2_second_half)
		for k, v in ipairs(l2_second_half) do
			if string.find(v, '^%x+') == nil then
				return nil
			end

			ipv6_addr_bin[k + idx_offset] = tonumber(v, 16)
			if ipv6_addr_bin[k + idx_offset] > 0xffff then
				return nil
			end			
		end
	end
	
	return ipv6_addr_bin
end

function is_mac_address(mac_addr)
	if mac_addr == nil then
		return false
	end

	local pattern = '^%x%x' .. string.rep(':%x%x', 5) .. '$'
	if string.find(mac_addr, pattern) == nil then
		return false
	else
		return true
	end
end

-- 192.168.0.188 dev br-lan lladdr 80:ce:62:39:21:fa REACHABLE
function ip_client_join(parted_data)
	if is_ip_address(parted_data[1]) ~= true then
		return
	end
	
	if parted_data[6] ~= "REACHABLE" then
		return
	end
	
	if is_mac_address(parted_data[5]) ~= true then
		return
	end

	-- ubus -S call alphawrt.client update_from_arp '{"mac_addr":"00:ca:fe:43:60:21","ip_addr":"192.168.0.20","interface":"br-lan"}'
	local command = "ubus -S call alphawrt.client update_from_arp "
	command = command .. "'{"
	command = command .. '"mac_addr":"' .. parted_data[5] .. '"'
	command = command .. ',"ip_addr":"' .. parted_data[1] .. '"'
	command = command .. ',"interface":"' .. parted_data[3] .. '"'
	command = command .. "}'"
	
	os.execute(command)
end

-- 2001:cafe:babe:1::65 dev br-lan lladdr 80:ce:62:39:21:fa REACHABLE
function ip6_client_join(parted_data)
	local ipv6_addr_bin = ipv6_add_str_2_bin(parted_data[1])
	if ipv6_addr_bin == nil then
		return
	end
	
	-- this condition is wrong, but lua 5.1 doesn't support bits & operator, so ...
	if ipv6_addr_bin[1] == 0xfe80 then
		-- skip link local address		
		return
	end
	
	if parted_data[6] ~= "REACHABLE" then
		return
	end
	
	if is_mac_address(parted_data[5]) ~= true then
		return
	end

	-- ubus -S call alphawrt.client update_from_arp '{"mac_addr":"00:ca:fe:43:60:21","ip_addr":"192.168.0.20","interface":"br-lan"}'
	local command = "ubus -S call alphawrt.client update_from_arp "
	command = command .. "'{"
	command = command .. '"mac_addr":"' .. parted_data[5] .. '"'
	command = command .. ',"ip6_addr":"' .. parted_data[1] .. '"'
	command = command .. ',"interface":"' .. parted_data[3] .. '"'
	command = command .. "}'"
	
	os.execute(command)
end

-- Deleted dev rai0 lladdr fc:25:3f:8e:5e:91 STALE
function ip_client_leave(parted_data)
	if parted_data[1] ~= "Deleted" then
		return
	end
	
	if is_mac_address(parted_data[5]) ~= true then
		return
	end
	
	-- ubus -S call alphawrt.client deactivate_client '{"mac_addr":"00:ca:fe:43:60:21"}'
	
	local command = "ubus -S call alphawrt.client deactivate_client "
	command = command .. "'{"
	command = command .. '"mac_addr":"' .. parted_data[5] .. '"'
	command = command .. "}'"
	
	os.execute(command)
end

local data_handlers = {
	ip_client_join,
	ip6_client_join,
	ip_client_leave
}

while 1 do
	local raw_data = io.read("*l")
	if raw_data == nil then
		break
	end

	--[[
		interested data format:
		192.168.0.188 dev br-lan lladdr 80:ce:62:39:21:fa REACHABLE
		2001:cafe:babe:1::65 dev br-lan lladdr 80:ce:62:39:21:fa REACHABLE
		Deleted dev rai0 lladdr fc:25:3f:8e:5e:91 STALE
	--]]
	local parted_data = split(raw_data, '%s+')

	for k, v in pairs(data_handlers) do
		v(parted_data)
	end
end
