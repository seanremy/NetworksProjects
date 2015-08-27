#TrafficAnalyzer.rb
#Performs domain-name-server lookup
#Sean Foley
#Implemented for my CSCI 4760 Networks class at the University of Georgia to demonstrate understanding of DNS
#I was taught by Dr. Kang Li in the Spring of 2015: http://cobweb.cs.uga.edu/~kangli/

#!/usr/bin/ruby
class MyNSLookup
  require 'socket'
  require 'timeout'
  
  serverIP = "8.8.8.8" #default serverIP
  if(!ARGV[0].nil?)
    serverIP = ARGV[0]
  end
  ip = serverIP.split(".")
  domainName = "google.com" #default domainName
  if(!ARGV[1].nil?)
    domainName = ARGV[1]
  end
  domainName = domainName.split(".")

  #socket
  sock = UDPSocket.new
  
  #Standard query A
  msg = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  for i in 0 ... domainName.size
    msg = msg + domainName[i].size.chr
    msg = msg + domainName[i]
  end
  msg = msg + "\x00\x00\x01\x00\x01"
  #send it
  sock.send(msg, 0, serverIP, 53)
  
  #receive A response
  r = "temp"
  res = Array.new
  found = false
  begin
    timeout(20) do
      #while valid data has not been received
      while(!found)
        r = sock.recvfrom(10000)
        #get query response into string
        res = Array.new
        for i in 0..r[0].size
          if(r[0][i].nil?)
            res[i] = 0
          else
            res[i] = r[0][i].ord
          end
        end
        #check if it's a valid response
        found = (res[0] == 0 && res[1] == 1)
      end
    end
  rescue Timeout::Error
    abort("ERROR: Query timed out\n")
  end
  
  #puts(ARGV[1] + "\n")
  
  #get list of ip's
  rnum = 256*res[6] + res[7]
  iplist = Array.new(rnum)
  for i in 0..rnum - 1
    ind = res.size - (rnum - 1 - i) * 16 - 5
    puts(res[ind].to_s + "." + res[ind + 1].to_s + "." + res[ind + 2].to_s + "." + res[ind + 3].to_s + "\n")
  end
  if(rnum == 0)
    puts("server cannot find domain")
  end
  sock.close
end
