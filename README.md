CableLabs R-PHY Automated Test Procedure Codebase
===========================


-Environment:- Pre-requisites and Dependencies  
-----------


1. **Fedora OS**
2. **Python 2.x** and **Python 3.x**
3. **Installing pip with sudo**  
    yum clean all  
    yum -y update  
    yum -y install python-pip   OR  
    python get-pip.py  
   **Verify the installation**  
    pip --help   
    pip -V  
4. **PyYAML**  
    link: https://pypi.python.org/pypi/PyYAML
    sudo pip install pyyaml OR
    sudo yum install python-yaml
5. **yamlordereddictloader**  
    link: https://pypi.python.org/pypi/yamlordereddictloader
    sudo pip install yamlordereddictloader
6. **pytest**  
    link: https://docs.pytest.org/en/latest/getting-started.html
    sudo pip install -U pytest
7. **pytest-html**  
    link: https://pypi.python.org/pypi/pytest-html
    sudo pip install pytest-html
8. **wireshark**  
    links:  
    
    https://www.dropbox.com/s/kfzm9ibibr9y182/wireshark-2.3.0-1.src.rpm?dl=0
    
    https://www.dropbox.com/s/i8z8s6iy3l8op7y/wireshark-2.3.0-1.tar.bz2?dl=0
    
    https://www.dropbox.com/s/8dzh51qxjxv5b2k/wireshark-2.3.0-1.x86_64.rpm?dl=0
    
    https://www.dropbox.com/s/q82dwornp4rsv7k/wireshark-qt-2.3.0-1.x86_64.rpm?dl=0
    
    https://www.dropbox.com/s/ir36riu2n4nst9e/README_wireshark-03222017_install_binaries.txt?dl=0
    >sudo yum install glib*  
    >sudo yum install qt5-qtmultimedia  
    >sudo yum install x11vnc (not sure if this is required)  
    >sudo rpm -ivh wireshark-2.3.0-1.x86_64.rpm  
    Preparing...                          ################################# [100%]  
    Updating / installing...  
    1:wireshark-2.3.0-1                ################################# [100%]  
    >sudo rpm -ivh wireshark-qt-2.3.0-1.x86_64.rpm  
    Preparing...                          ################################# [100%] 
    Updating / installing...  
    1:wireshark-qt-2.3.0-1             ################################# [100%]  
    
9. **Git Clone**:  
    ```
    mkdir YOUR_TEST_PATH
    cd YOUR_TEST_PATH
    git clone https://github.com/CableLabs-ATP-Automation/cablelab-atp-automation.git
    cd cablelab-atp-automation
    git checkout -b <your branch name> master
    git status
    git branch
    
    To merge to your local branch:
    git add file 1, file 2, file 3, etc,
    git commit -m "Comments"
    git push origin <your branch name>
    Finally put in a merge request through github
    ```
10. **Apache server establish(optional)**:  
    http://httpd.apache.org/docs/2.4/install.html
    ```
    Download	
        Download the latest release from http://httpd.apache.org/download.cgi
    Extract	
        $ gzip -d httpd-NN.tar.gz
        $ tar xvf httpd-NN.tar
        $ cd httpd-NN
    Configure	
        $ ./configure --prefix=PREFIX
    Compile	
        $ make
    Install	
        $ make install
    Customize	
        $ vi PREFIX/conf/httpd.conf
    Test	
        $ PREFIX/bin/apachectl -k start
    NN must be replaced with the current version number, and PREFIX must be replaced with the filesystem path under which the server should be installed. If PREFIX is not specified, it defaults to /usr/local/apache2.
    
    Each section of the compilation and installation process is described in more detail below, beginning with the requirements for compiling and installing Apache httpd. 
    
    You should then be able to request your first document via the URL http://localhost/
    ```
---------   
- Run Test:
------------
1. **Put your oringinal .pcap file under**:
    ```
    ./original_pcap
    ```
2. **Modify the config.yaml file to selcet the procedure need to run**:
    ```
    ./config/config.yaml
    ```
3. **Run the script**:
    ```
    python3 atp_pytest.py OR python atp_pytest.py (will execute all procedures in config.yaml file)
    python3 atp_pytest.py <procedure index> OR python atp_pytest.py <procedure index>(will execute procedures with specific index)
    Example :
    python atp_pytest.py 13 21 22 23 25 (the 13,21,22,23,25 procedure will execute)
    ```
4. **After the script done, Find the report and log under**:
    ```
    ./log/<timestamp>/log_<timestamp>.html
    ./log/<timestamp>/atp_log_<timestamp>.log
    ```
    
----------
- Develop Cases:
---------

1. **Genrate New .yaml file for each procedure under**:
    ```
    ./data
    ```
     **Here is the sample(not real cases, only an example):**  
    ```yaml  
    source:
        #define the locally variable within this block
        #to use these variable, you can use $var_name$ to call them in filter command or test cases
        procedure_name: "#21_L2TPv3_Control_messages"
        ip_proto: "0x73"
        ip_ttl: "0xff"
        l2tp_session_id: "0"
        l2tp_ccid: "0"

    filter:
        #define all the filters used for test cases as below:
        DHCP_ACK: # this is the filter name which will used to display for report
            skip:
            #(optional) list the skip condition according to variable value, which means such filter will be skiped when met the condition list here
                - $ccap_to_rpd_CDN$: False 
            instance: 
            #these instances use to store the pcap file and xml file filtered out by filter command
                - pcap_DHCP_ACK: $procedure_name$_pcap_DHCP_ACK.pcap
                - xml_DHCP_ACK: $procedure_name$_xml_DHCP_ACK.xml
            input: $pcap_file$
            #this is the original pcap file which will used to filter
            match: 'bootp.hw.mac_addr == $rpd_mac_addr$ and (udp.port == 67 or udp.port == 68) and bootp.option.dhcp == 5'
            #this is the filter command, detail structure please refor to wireshark filter
            assign:
            #(optional), if need, we can assign some locally variable here from filter directly for future use
                dhcp_ack_time: get_show("//field[@name='frame.time_epoch']")
                
        CCAP_to_RPD:
            instance: 
                - pcap_CCAP_to_RPD: $procedure_name$_pcap_CCAP_to_RPD.pcap
                - xml_CCAP_to_RPD: $procedure_name$_xml_CCAP_to_RPD.xml
            input: $pcap_file$
            match: 'ip.src == $ccap_core_ip$ && frame.time_epoch >= $dhcp_ack_time$ && ip.dst == $rpd_ip$ && ip.ttl == $ip_ttl$ && ip.proto == $ip_proto$ && l2tp.sid == $l2tp_session_id$ && l2tp.ccid == $l2tp_ccid$'
    
       
            ....
 
      
    testcase:
    #list all the test cases below, these cases are seperated by different filtered out xml file
        CCAP_to_RPD:
            #this is the name of such cases
            input: $xml_CCAP_to_RPD$
            #this is the filtered out xml file which will be use to execute these checkpoint below
            skip:
            #(optional)  list the skip condition according to variable value, which means all the checkpoints will be skiped when met the condition list here 
                - $CCAP_to_RPD_DSCP_other$: False
                - "$#21.8$": False
              
            checkpoint:
            #checkpoint structure is:
            #{case_number}{case_info}{case_action}{xpath/express}: expected result/sub checkpoints
            #the case_action supported until now :
            #   {identify_field}:  if there are some fields with same name, need to identify such field with specific sub-field value firstly, then execute the sub-checkpoints within it.
            #   {compare_value}: compare the value got from xml file with expected results, the expected result can be a list or variable name assigned before
            #   {start_bits}: compare the specific start bits of specific field with expected results.
            #   {not_exist}: provide a judgement of specific field not exist in filtered packets
            #   {exist}: provide a judgement of specific field exist in filtered packets
            #   {get_number_field}: compare the number of fields meet the specific condition with expected number
            #   {store_value}: store the value get from specific field with the assigned variable name to local name space(can be called within the procedure)
            #   {store_value_global}: store the value get from specific field with the assigned variable name to global name space(can be called in/out the procedure)
            #   {out_range}: provide a judement of specific field value out of expected range [startpoint, endpoint]
            #   {in_range}: provide a judement of specific field value in expected range [startpoint, endpoint]
            #   {include_value}: provide a judement of expected value included in field values get from xml
            #   {calculate_value}: execute the specific express with stored variables then store the calculated value to another local varialbe(can be called within the procedure)
            #   {calculate_value_global}: execute the specific express with stored variables then store the calculated value to another global varialbe(can be called in/out the procedure)
              "{#21.5}{Filter out the packets for the l2tp Session ID =0 for control packets }{identify_field}{//field[@show='1'][@name='l2tp.type']...}": 
                  "{#21.5.1}{Verify T bit for control packets using lt2p.l2_spec_t}{compare_value}{field[@name='l2tp.type']}": [1]
                  "{#21.5.2}{Verify the length bit for control packets using l2tp.length_bit}{store_value}{field[@name='l2tp.length_bit']}": "$length_bit$"
                  "{#21.5.3}{Verify the Sequence bit using l2tp.seq_bit}{not_exist}{field[@name='l2tp.seq_bit']}": [0]
                  "{#21.5.4}{Verify that the first 12 bits of the L2TPv3 Control Header}{start_bits}": "0b110010000000"
                  
              "{#21.6}{Identify SCCRQ in the filtered packets }{identify_field}{//field[@show='1'][@name='l2tp.avp.message_type']...}": 
                  "{#21.6.1}{Verify M, H, and Resv bits }{start_bits}": "0b100000"
                  "{#21.6.2}{Verify Vendor ID for the AVP, l2tp.avp.vendor_id == 0/4491}{compare_value}{field[@name='l2tp.avp.vendor_id']}": [0,4491]
                  "{#21.6.3}{Verify Attribute Type l2tp.avp.type == 0 indicating Message Type}{compare_value}{field[@name='l2tp.avp.type']}": [0]
                  "{#21.6.4}{Verify Attribute Value is 1}{compare_value}{field[@name='l2tp.avp.message_type']}": [1]
                  
             ....
                  
        
            ....
             
    ```
    
    
2. **Modify the configuration .yaml file called config.yaml**:
    ```
    ./config/config.yaml
    ```
    **Here is the sample:**  
    ```yaml
    basic_config: 
    # add some global variable as below: 
    
    pcap_file: rpd_boot.pcap #this is the origin pcap file to be analyzed
    ccap_core_ip: 10.10.17.1 
    rpd_ip: 10.10.17.36
    rpd_mac_addr: 00:04:9f:32:17:99
    
    captureTLV: #record the TLV length and value below for future use
        "62.1":  # TLV type
          length: 1 # TLV length
          value: 2 # TLV value
        "62.2":
          length: 6
          value: "00:fe:c8:05:dc:b8"
        "50.18": 
          length: 1
          value: 4
    
    # add the list of procedures that needs to be run as shown below. All of the procedures listed below will be run
    procedure:
        21:
            name: "#21_L2TPv3_Control_messages"
            data_file: "#21_L2TPv3_Control_messages.yaml"
    
        23:
            #provide the name of such procedure which will displayed in report
            name: "procedure name displayed in report" 
            #provide the name of procedure yaml file name will be uesed to run cases
            data_file: "procedure yaml file to run cases"
    
       
    ```


    
 

 



    
