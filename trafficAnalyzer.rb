#TrafficAnalyzer.rb
#Analyzes tcp stream dump files and separates the conversations into different text files
#Sean Foley
#Implemented for my CSCI 4760 Networks class at the University of Georgia to demonstrate understanding of packet header formatting
#I was taught by Dr. Kang Li in the Spring of 2015: http://cobweb.cs.uga.edu/~kangli/

class TrafficAnalyzer
	str = File.open(ARGV[0], "rb") {|f| f.read} #open command line file
	count = 0 #keeps packet count
	convocount = 0 #keeps conversation count
	convopackets = [1] #keeps counts of packets in each conversation
	addsa = [] #keeps the source addresses
	ports = [] #keeps the source ports
	addca = [] #keeps destination addresses
	portc = [] #keeps the destination ports
	sflow = ["str"] #all the sent packets
	cflow = ["str"] #all the captured packets
	place = 24 #start after the global header
	ipv = 4 #keeps track of ipv4 or ipv6

	src = 0, dest = 0 #address variables
	while (place < str.length) #loop through pcap file
		#calculate length from 4-byte length part of header (little-endian hexadecimal)
		length = str[place + 8].ord + 256 * str[place + 9].ord + 65536 * str[place + 10].ord + 16777216 * str[place + 11].ord
		#ipv = str[place + 30].ord / 16 #gets ip version (first 4 bits of first ip byte)
		iplen = 4*(str[place + 30].ord % 16) #gets ip header length (last 4 bits of first ip byte)
		off1 = 12
		off2 = 16

		#get source address
		adds = (str[place + 30 + off1].ord.to_s + "." + str[place + 31 + off1].ord.to_s + "." + str[place + 32 + off1].ord.to_s + "." + str[place + 33 + off1].ord.to_s)
		#get source port
		sport = (str[place + 30 + iplen].ord * 256 + str[place + 31 + iplen].ord)
		#get destination address
		addc = (str[place + 30 + off2].ord.to_s + "." + str[place + 31 + off2].ord.to_s + "." + str[place + 32 + off2].ord.to_s + "." + str[place + 33 + off2].ord.to_s)
		#get destination port
		cport = (str[place + 32 + iplen].ord * 256 + str[place + 33 + iplen].ord)
		#check if this is an already existing conversation
		found = false
		mark = -1
		for i in 0 .. convocount + 1
			if adds == addsa[i] && addc == addca[i] || adds == addca[i] && addc == addsa[i] #if addresses match
				if sport == ports[i] && cport == portc[i] || sport == portc[i] && cport == ports[i] #if ports match
					found = true
					mark = i
				end
			end
		end
		if !found #if convo does not already exist, add it
			addsa[convocount] = adds
			addca[convocount] = addc
			ports[convocount] = sport
			portc[convocount] = cport
			sflow[convocount] = str[place + 16, length]
			cflow[convocount] = ""
			convocount = convocount + 1
			convopackets[convocount] = 1
		else #if convo already exists, append packet to it
			dir = (adds == addsa[mark])
			if(dir) #if sent
				sflow[mark] = sflow[mark] + str[place + 16, length]
			else
				cflow[mark] = cflow[mark] + str[place + 16, length]
			end
			convopackets[mark] = convopackets[mark] + 1
		end

		place = place + length + 16 #increment place by packet size + header size (16)
		count = count + 1 #increment packet count
	end

	#write to file
	stat = ARGV[0].to_s + ".stat"
	data = "Total packet count: " + count.to_s + "\n"
	for i in 1..(convocount)
		data = data + "Flow " + i.to_s + " packet count: " + convopackets[i].to_s + "\n"
		sn = ARGV[0].to_s + ".f" + i.to_s + ".s"
		cn = ARGV[0].to_s + ".f" + i.to_s + ".c"
		open(sn, 'w') {|f| f.puts(sflow[i - 1])}
		open(cn, 'w') {|f| f.puts(cflow[i - 1])}
	end
	open(stat, 'w') {|f| f.puts(data)}
end
