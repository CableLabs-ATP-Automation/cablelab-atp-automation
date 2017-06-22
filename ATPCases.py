
try :
    
    import logging
    import logging.config
    import os,sys,re
    import traceback
    from ATPComOpt import XML_analyze
    from ATPComOpt import test_case_analyze, convert_str, var_assign, convert_express, case_result_fulfill
    import yamlordereddictloader
    import yaml
    py3 = sys.version_info[0] > 2 #creates boolean value for test that Python major version > 2
    
    if py3:
        from subprocess import DEVNULL, check_call
    else:
        from subprocess import check_call
 
except ImportError as e:
    raise ImportError (str(e) + """
    A critical module was not found. Probably this operating system does not
    support it. Please fix the import error before running the test.""")

log = logging.getLogger(__name__)



#################################################################################
# procedure running class
# Execute the procedure according to the data_file
################################################################################# 

                
class Procedure_run():
    def __init__(self, procedure_data_file, test_data, filtered_file_path, pcap_file_path):
        #################################################################################
        #  Step1 :Get all the infomations from the data file
        #################################################################################     
        #=======================================================================
        #test_results dict store the test results of each executed items to displayed by report
        #
        #test_results = {
        #                "result":"PASS", 
        #                "procedure_execute_info": "All Cases Test PASS", 
        #                "cases":{
        #                        "case_number":{ 
        #                                    "case_expected_result": expected_result,
        #                                    "case_actully_result": actually_result,
        #                                    "result": PASS/FAIL/SKIP/BLOCK,
        #                                    "case_info": case_info
        #                                       }
        #                        },
        #                "filters":{
        #                        "filter_name": filter_result
        #                         }
        #                 }
        #===========================================================================
        # test_data dict store the variables can be call during test execution
        #
        # test_data = {
        #                "local_var":{
        #                            "local_var_name": local_var_value,
        #                            "filter_name": True,
        #                            "xml_file_name": packets_number
        #                            },
        #                "global_var":{
        #                            "global_var_name": global_car_name,
        #                            "case_number":True
        #                            },
        #                }
        #=======================================================================
        self.result = "PASS"
        self.procedure_execute_info = "All Cases Test PASS"
        self.cases = {}
        self.filters = {}
        
        try:
            self.test_data = test_data
            self.procedure_data = yaml.load(open(procedure_data_file), Loader=yamlordereddictloader.Loader)
            self.procedure_var_list = self.procedure_data["source"]
            for procedure_var in self.procedure_var_list:
                self.test_data["local_var"][procedure_var] = self.procedure_var_list[procedure_var]
            self.procedure_name = self.procedure_var_list["procedure_name"]
            self.filtered_file_path = filtered_file_path
            self.pcap_file_path = pcap_file_path
            self.procedure_filter_list = self.procedure_data["filter"]
            #print (self.procedure_filter_list)
            self.procedure_testcase_list = self.procedure_data["testcase"]
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            self.result = "ERROR"
            self.procedure_execute_info = "Got procedure infomation from data file Got Error"
            log.error(self.procedure_execute_info)
            
    def procedureExecution(self):        
        #################################################################################
        #  Step2 :Execute all the filters according to the data file
        ################################################################################# 
        
        log.info("===Start to execute the filters ===" )
        try:
            filter_number = 0
            #print ("------", self.procedure_filter_list)
            if self.procedure_filter_list:
                for filter_name in self.procedure_filter_list:
                    procedure_filter = self.procedure_filter_list[filter_name]
                    self.test_data["local_var"][filter_name] = True
                    filter_number += 1
                    log.info("===Execute %s filter===" % filter_number)
                    
                    filter_instances_list = procedure_filter["instance"]
                    #assign the instance variable
                    for filter_instances_dict in filter_instances_list:                    
    
                        var_assign(filter_instances_dict, self.test_data, "local")
                    #checkout the pacap file variable
                    for key in filter_instances_list[0]:
                        target_pcap_file_name = convert_str(filter_instances_list[0][key], self.test_data)
                        target_pcap_file = os.path.join(self.filtered_file_path, target_pcap_file_name)
                    #checkout the xml file variable    
                    for key in filter_instances_list[1]:
                        target_xml_file_name = convert_str(filter_instances_list[1][key], self.test_data)
                        if target_xml_file_name:
                            target_xml_file = os.path.join(self.filtered_file_path, target_xml_file_name)
                        
                        else:
                            target_xml_file = None
                        
                    source_pcap_file_name = convert_str(procedure_filter["input"], self.test_data)
                    source_pcap_file = os.path.join(self.pcap_file_path, source_pcap_file_name)
                    #if there source pcap file is not the original pcap file, try to find it under filtered files.
                    if not os.path.isfile(source_pcap_file):
                        source_pcap_file = os.path.join(self.filtered_file_path, source_pcap_file_name)
                    #if pcap file can not find ether under original file path and filtered file path.    
                    if not os.path.isfile(source_pcap_file):
                        filter_result = "Can not find source pcap file, filter Fail"
                        self.test_data["local_var"][filter_name] = False
                        log.info(filter_result)
                        
                    else:
                        filter_cmd = procedure_filter["match"]
                        ##############################################################
                        #  Check the skip config to check if the filter will be skiped #
                        ############################################################## 
                        filter_skip_flag = False
                        if "skip" in procedure_filter:
                            skips = procedure_filter["skip"]
                            for skip in skips:
                                for key in skip:
                                    key_value = convert_express(key, self.test_data)
                                    log.debug (key)
                                    log.debug (key_value)
                                    if key_value == skip[key]:
                                        filter_skip_flag = True
                                        filter_skip_reason = "Skip such filter as %s = %s" % (key, key_value)
                        if filter_skip_flag:
                            #if skip such filter, set such filter result as False, and packets number as 0
                            self.test_data["local_var"][target_xml_file] = 0
                            self.test_data["local_var"][filter_name] = False
                            filter_result= filter_skip_reason
                            
                        else:
                            
                            log.info("===Start to filter out the packets ===" )
                            log.info("Start to handle the filter---%s" % filter_cmd)
                            filter_cmd = convert_str(filter_cmd,self.test_data)
                            if filter_cmd:
                                
                                log.info(" The filter command %s" % filter_cmd)
                                fil = Filter_execution(filter_name, source_pcap_file, target_pcap_file, target_xml_file, filter_cmd, self.test_data)
                                filter_result = fil.filterTofile()
                                #handle assign part of filters
                                #assign the value to variable
                                if "assign" in procedure_filter:
                                    assign_dict = procedure_filter["assign"]
                
                                    for key in assign_dict:
                                        
                                        fil.checkXml(key, assign_dict[key])
                                else:
                                    pass
                            else:
                                self.result = "ERROR"
                                self.procedure_execute_info = \
                                    "Can not get expect value in val_dict, please check the data_file"
                                filter_result = self.procedure_execute_info
                                log.error(self.procedure_execute_info)
                    self.filters[filter_name] = filter_result 
                    log.info(filter_result)           
                    log.info("=========filter %s Done==========" % filter_number)
                else:
                    log.info("No filters need to do")
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            self.result = "ERROR"
            self.procedure_execute_info = \
                "filter pcap file Got Error"
            log.error(self.procedure_execute_info)
            
            
        
        #################################################################
        #  Step3 :Execute all the test cases according to the data file #
        #################################################################        
        
        log.info("===Start to execute the test cases ===" )

        try :            
            for test_case_name in self.procedure_testcase_list:
                test_case = self.procedure_testcase_list[test_case_name]
                skip_flag = False
                ##############################################################
                #  Check the skip config to check if the case will be skiped #
                ##############################################################  
                if "skip" in test_case:
                    skips = test_case["skip"]
                    for skip in skips:
                        for key in skip:
                            key_value = convert_express(key, self.test_data)
                            if key_value == skip[key]:
                                skip_flag = True
                                skip_reason = "Test cases skiped as %s = %s" % (key, key_value)
                                break
                    
                log.info("Start to execute testcase %s" % test_case_name)
                test_case_input = test_case["input"]
                
                test_detail_cases = test_case["checkpoint"]
                if skip_flag:
                    #if skip such case, set all cases below as skipped and fill with skip reason
                    cases_results_dict = case_result_fulfill(test_detail_cases, "SKIPED", skip_reason)
                else:
                    if test_case_input == "check_TLV":
                        xml_file = None
                        tc = TC_execution(xml_file,test_detail_cases,self.test_data)
                        cases_results_dict = tc.tcExecution()
                    else:
                        xml_file_name = convert_str(test_case_input, self.test_data)    
                        packet_number = 0
                        if xml_file_name:
                            xml_file = os.path.join(self.filtered_file_path, xml_file_name)
                            if xml_file in self.test_data["local_var"]:
                                packet_number = self.test_data["local_var"][xml_file]
                            
                                if  packet_number == 0 :
                                    self.result = "FAIL"
                                    self.procedure_execute_info = \
                                        "There is no Packet filtered out in %s " % xml_file
                                    
                                    log.info(self.procedure_execute_info)
                                    cases_results_dict = case_result_fulfill(test_detail_cases, "BLOCKED", self.procedure_execute_info)
                                else: 
                                    tc = TC_execution(xml_file,test_detail_cases,self.test_data)
                                    cases_results_dict = tc.tcExecution()                           
        
                            else:
                                
                                self.result = "ERROR"
                                self.procedure_execute_info = \
                                    "There is no %s found, pleae check the data_file " % xml_file
                                cases_results_dict = case_result_fulfill(test_detail_cases, "BLOCKED", self.procedure_execute_info)
                                log.error(self.procedure_execute_info)
                                
                        else:                
                            self.result = "ERROR"
                            self.procedure_execute_info = \
                                "There is no xml file found, pleae check the data_file"
                            cases_results_dict = case_result_fulfill(test_detail_cases, "BLOCKED", self.procedure_execute_info)    
                            log.error(self.procedure_execute_info)
                    
                
                self.cases = dict(self.cases, **cases_results_dict)
                    
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            self.result = "ERROR"
            self.procedure_execute_info = \
                "Test cases exection Got Error"
            log.error(self.procedure_execute_info)
        test_results = {}
        test_results["result"] = self.result
        test_results["procedure_execute_info"] = self.procedure_execute_info
        test_results["cases"] = self.cases
        test_results["filters"] = self.filters
        return test_results 
    
#################################################################################
# filter execution procedure
# Execute the filters to generate xml file for cases execution 
#################################################################################     
        
        
class Filter_execution():
    
    def __init__(self, filter_name, source_pcap_filename, target_pcap_file, target_xml_file, filter_cmd, test_data):
        
        self.source_pcap_filename = source_pcap_filename
        self.filter_cmd = filter_cmd
        self.target_pcap_file = target_pcap_file
        self.target_xml_file = target_xml_file
        self.test_data = test_data
        self.filter_name = filter_name
        self.packets_count = 0
        self.filter_result = None
        
        
    def filterTofile(self):
        log.info ('try to get the temp file with filter')
        log.info ('this will cost several minuts, please wait ...')
        #################################################################################
        # Use tshark to filterout according to the filter command
        # Then generate the filtered pcap file and xml file
        #################################################################################  
        try:
            if py3:
                tshark_status = check_call(["tshark", "-2", "-r", self.source_pcap_filename, "-R", self.filter_cmd, "-w", self.target_pcap_file],stdout=DEVNULL, stderr=DEVNULL)
            else:
                FNULL = open(os.devnull, 'w')
                tshark_status = check_call(["tshark", "-2", "-r", self.source_pcap_filename, "-R", self.filter_cmd, "-w", self.target_pcap_file],stdout=FNULL, stderr=FNULL)
            if tshark_status == 0:
                log.info('pcap temp file %s generate sucessfully' % self.target_pcap_file)
                count_str = os.popen('capinfos -c %s' % self.target_pcap_file).read()
                self.packets_count = int(re.search(r'Number of packets:\s+(\d+)', count_str).group(1))
                self.filter_result = "There are %d packets filtered out" % self.packets_count
                log.info (self.filter_result) 
                self.test_data["local_var"][self.target_xml_file] = self.packets_count
                if self.packets_count == 0:
                    self.test_data["local_var"][self.filter_name] = False
                else:
                    pass
                if self.target_xml_file: 
                    with open(self.target_xml_file, "w") as xml_file:
                        if py3:
                            xml_status = check_call(["tshark", "-r", self.target_pcap_file, "-T", "pdml"],stdout=xml_file, stderr=DEVNULL)
                        else:    
                            xml_status = check_call(["tshark", "-r", self.target_pcap_file, "-T", "pdml"],stdout=xml_file, stderr=FNULL)
                    if xml_status == 0:
                        log.info('xml temp file %s generate sucessfully' % self.target_xml_file)
                    else:
                        log.error("generate xml file Got Error")
                        self.test_data["local_var"][self.filter_name] = False
                else:
                    pass
            else:
                
                self.filter_result = "filter pcap file Got Error"
                self.test_data["local_var"][self.filter_name] = False
                log.error(self.filter_result)
                
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            self.filter_result = "filter pcap file Got Error"
            log.error(self.filter_result)
            self.test_data["local_var"][self.filter_name] = False
            
        return self.filter_result
    
    #################################################################################
    # Analyze the xml file to handle assign part of filters
    # Assign the var with the value got from filtered files
    #################################################################################         
            
    def checkXml(self, val, command):
        if command == "packets_number":
            self.test_data["local_var"][val]=self.packets_count
        else:
            if self.packets_count == 0:
                log.info ("There is no packets found by filter, can not execute, blocked")
                self.test_data["local_var"][val]=None
            else:
                
                self.tree = XML_analyze(self.target_xml_file)
                log.info ("trying to store value for %s" % val)
                command = "self.tree.%s" % command
                value_list = eval(command)
                if len(value_list) == 1:
                    self.test_data["local_var"][val]=value_list[0]
                    log.info ("The value got for %s is %s" % (val,value_list[0]))
                elif len(value_list) > 1:
                    log.info ("There are too many values got, please check the xpath command")
                    self.test_data["local_var"][val]=None
                else:
                    log.info ("There are No value got, please check the xpath command")
                    self.test_data["local_var"][val]=None
                    




#################################################################################
# Test_cases execution procedure
# Execute the cases , return test cases results 
#################################################################################  

class TC_execution():
    
    def __init__(self, xml_file, test_cases, test_data):
        self.test_cases = test_cases
        self.test_data = test_data
        self.xml_file = xml_file
        
    def tcExecution(self):
        #initial cases results
        cases_results_dict = {}               
        for keys in self.test_cases.keys():
            try : 
                val = self.test_cases[keys]
                #get cases infomation for test
                case_number, case_info, case_action, xpath = test_case_analyze(keys)                
                elem = None
                cases_results_dict[case_number] ={}
                #exectue cases in order
                case_execute = Case_action(self.xml_file, case_number, case_info, xpath, elem, val, self.test_data)
                cases_results_dict_new = getattr(case_execute, case_action)()
                #merge the results to generate total results
                cases_results_dict = dict(cases_results_dict, **cases_results_dict_new)    
            except Exception as e:
                traceback.print_exc()
                log.error(str(e))
                log.error("test cases execution Got Error")
                cases_results_dict[case_number]["case_actully_result"] = "test cases execution Got Error"
                cases_results_dict[case_number]["result"] = "ERROR" 
        return cases_results_dict
    
 
#################################################################################
# Test_cases detail execution steps
# Execute the cases according to the case action
# Return the test case result for each case
#################################################################################   
 
class Case_action():
    
    def __init__(self, xml_file, case_number, case_info, xpath, elem, val, test_data):
        self.case_number = case_number
        self.case_info = case_info
        self.xpath = xpath
        self.elem = elem
        self.val = val
        self.xml_file = xml_file
        self.test_data = test_data        
        self.pass_print = "++++++++++++Test Cases %s ----> Pass" % case_number
        self.fail_print = "************Test Cases %s ----> Fail" % case_number
        self.tree = XML_analyze(self.xml_file)
        
        self.cases_results_dict = {}
        self.cases_results_dict[case_number]={}
        self.cases_expected_result = None
        self.cases_actully_result = None
        self.case_result = "PASS"
        log.info ("==========Test Cases %s=============" % self.case_number) 
    #################################################################################
    #  Handle the "identify_field" action,
    #  When field identified correcly, start to execute the sub-cases under such field
    #  If not, block all the cases below
    #################################################################################
    def identify_field(self):
        log.info("Start to identify the name blank field according to value")
        elem_list = self.tree.identify_field(self.xpath)
        self.cases_expected_result = "Identify SUCCESS"

        if len(elem_list) >= 1:

            log.info("There are %s packets contains same field %s" % (len(elem_list), self.xpath))
            log.info("The sub cases will be run for %s times" % len(elem_list))
            log.info(self.pass_print)
            log.info ("identify_field field by |%s| success" % self.xpath)
            self.cases_actully_result = self.cases_expected_result
            sub_case_execute = 0
            for elem in elem_list:
                sub_case_execute += 1
                log.info("===The sub cases %s times run start===" % sub_case_execute)
                for sub_keys in self.val.keys():
                    sub_val = self.val[sub_keys]
                    sub_case_number, sub_case_info, sub_case_action, sub_xpath = test_case_analyze(sub_keys)
                    
                    self.cases_results_dict[sub_case_number] ={}
                    case_execute = Case_action(self.xml_file, sub_case_number,sub_case_info, sub_xpath, elem, sub_val, self.test_data)
                    
                    cases_results_dict_new = getattr(case_execute, sub_case_action)()
                    self.cases_results_dict = dict(self.cases_results_dict, **cases_results_dict_new)
                    
                log.info("===The sub cases %s times run Done===" % sub_case_execute)
            log.info("====All sub cases run Done====")        
        else:
            self.case_result = "FAIL"
            log.info("No  |%s|  found in captured packets" % self.xpath)
            self.cases_actully_result = "Can not identify field correctly"
            block_reason = "Blocked by case |%s|" % self.case_number
            cases_results_dict_new = case_result_fulfill(self.val, "BLOCKED", block_reason)
            self.cases_results_dict = dict(self.cases_results_dict, **cases_results_dict_new)
            log.info(self.fail_print)
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "exist" action: 
    #  Get all the values according to the xpath.
    #  If val contains in these values--Test Pass.
    #  Else---Test Fail
    ################################################################################# 
    def exist(self):
        
        log.info("Start to check all fields according to value")
        self.cases_expected_result = "%s exist" % self.val
        value_list = self.tree.get_show(self.xpath)
        log.info("The %s contains %s" % (self.xpath, value_list))
        intersection = list(set(self.val) & set(value_list))
        self.cases_actully_result = "The value got : %s" % value_list
        if len(intersection) > 0:
            self.case_result = "PASS"
            log.info ("The %s= %s contains in packet --- Test Pass" % (self.xpath, self.val))
                     
            log.info(self.pass_print)
        else:
            self.case_result = "FAIL"
            log.info ("The %s= %s Not exist in packet --- Test Fail" % (self.xpath, self.val))
            log.info("%s Not exist" % self.val)         
          
            log.info(self.fail_print)
    
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "not_exist" action: 
    #  Get all the values according to the xpath.
    #  If val Not contains in these values--Test Pass.
    #  Else---Test Fail
    #################################################################################   
    def not_exist(self):

        log.info("Start to check all fields according to value")
        self.cases_expected_result = "%s Not exist" % self.val
        value_list = self.tree.get_show(self.xpath)
        log.info("The %s contains %s" % (self.xpath, value_list))
        intersection = list(set(self.val) & set(value_list))
        unitsection = list(set(self.val) | set(value_list))
        self.cases_actully_result = "The value got : %s" % value_list
        if len(intersection) == 0 and len(unitsection) > 0:
            self.case_result = "PASS"
            log.info("The %s= %s Not exist in packet --- Test Pass" % (self.xpath, self.val))
            log.info("%s Not exist" % self.val) 
            log.info(self.pass_print)
        else:
            self.case_result = "FAIL"
            log.info("The %s= %s exist in packet --- Test Fail" % (self.xpath, self.val))
            log.info("%s exist" % self.val)
            log.info(self.fail_print)
        
        
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
#===============================================================================
#    Replaced by compare_value method
#
#    def get_show(self):
#         value_list = self.tree.get_show(self.xpath, self.elem)
#         log.info("%s expected value = %s" %(self.xpath, self.val))
#         self.cases_expected_result = "%s " % self.val
#         log.info("%s actual value = %s" % (self.xpath, value_list))
#         if len(value_list) > 0:
#             if set(value_list).issubset(set(self.val)):
#                 self.case_result = "PASS"
#                 log.info("%s actual value is %s is same as expected %s" % (self.xpath, value_list, self.val))
#                 self.cases_actully_result =  "%s " % value_list               
#                 log.info(self.pass_print)
#             else:
#                 self.case_result = "FAIL"
#                 log.info("%s actual value is %s is NOT same as expected %s" % (self.xpath, value_list, self.val))
#                 self.cases_actully_result =  "%s " % value_list               
#                 log.info(self.fail_print)  
# 
#         else:
#             self.case_result = "FAIL"
#             self.cases_actully_result = \
#                 "%s can not get" % self.xpath
#             log.info(self.cases_actully_result)
#             log.info(self.fail_print)
#             
#         self.cases_results_dict = self._case_dict_generate()
#         
#         return self.cases_results_dict
#     
#===============================================================================
    
    #################################################################################
    #  Start to handle the "get_number_field" action: 
    #  1. Get the value_list according to the xpath.
    #  2. Calculate the length of Value_list to indicate the nubmers of these fields
    #  If the value contains in val --Test Pass.
    #  Else---Test Fail
    #################################################################################          
    def get_number_field(self):
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("Start to get value for %s" % self.val)
        expect_number = convert_express(self.val, self.test_data)
        self.cases_expected_result = "Expected number of field %s = %s" %(self.xpath, expect_number)
        log.info("Expected number of field %s = %s" %(self.xpath, expect_number))
        log.info("Actual number of field %s = %s" % (self.xpath, len(value_list))) 
        self.cases_actully_result =  "Actual number of field %s = %s" % (self.xpath, len(value_list))               
        if expect_number:
            if len(value_list) == expect_number:
                self.case_result = "PASS"
                log.info("%s filed actual number is %s same as expected %s " % (self.xpath,len(value_list),expect_number))                
                log.info(self.pass_print)
            else:
                self.case_result = "FAIL"
                log.info("%s filed actual number is %s NOT same as expected %s " % (self.xpath,len(value_list),expect_number))  
                log.info(self.fail_print)
        else:
            log.info("can not get value for %s, please check the data_file" % self.val)
            log.info(self.fail_print)  
            self.case_result = "FAIL"        
    
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "start_bits" action: 
    #  Get the start-bits of identified field.
    #  If the start-bit equals to val --Test Pass.
    #  Else---Test Fail
    #################################################################################     
    def start_bits(self):
        log.info("Start to handle start_bits")
        log.info("The expected start value is %r" % self.val)
        start_bits = self.tree.get_start_bits(self.elem)
        self.cases_expected_result = "%s" % self.val
        self.cases_actully_result =  "%s" % start_bits           
        if start_bits:
            log.info("The actual start value is %s" % start_bits)           
            if re.match(self.val, start_bits):
                log.info("The actual start %s value same as expected %s" % (start_bits, self.val))
                log.info(self.pass_print)  
                self.case_result = "PASS" 
            else:
                log.info("The actual start %s value Not same as expected %s" % (start_bits, self.val))
                log.info(self.fail_print)  
                self.case_result = "FAIL" 
        else:
            log.info("Can not get start bits")           
            log.info(self.fail_print)  
            self.case_result = "FAIL" 
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "compare_value" action: 
    #  1. Get the value by xpath.
    #  2. Get the expected value by val express from var_dict(test_data).
    #  3. Or compare with the value of val directly
    #  If the value equals expected value --Test Pass.
    #  Else---Test Fail
    ################################################################################# 
    def compare_value(self):
        log.info("Start to handle compare value task")
        expect_value_list = []
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("%s actual value = %s" % (self.xpath, value_list))
        expect_value = convert_express(self.val, self.test_data)
        self.cases_expected_result = "%s" % expect_value
        self.cases_actully_result =  "%s" % value_list     
        if isinstance(expect_value, list):
            expect_value_list = expect_value
        else:
            if expect_value:            
                expect_value_list.append(expect_value)
            else:
                pass
            
        if len(expect_value_list) > 0:
            if len(value_list) > 0:
                if set(value_list).issubset(set(expect_value_list)):
                    self.case_result = "PASS"
                    log.info("%s actual value is %s is same as expected %s" % (self.xpath, value_list, expect_value_list))
                    self.cases_actully_result =  "%s " % value_list               
                    log.info(self.pass_print)
                else:
                    self.case_result = "FAIL"
                    log.info("%s actual value is %s is NOT same as expected %s" % (self.xpath, value_list, expect_value_list))
                    self.cases_actully_result =  "%s " % value_list               
                    log.info(self.fail_print)  
    
            else:
                self.case_result = "FAIL"
                self.cases_actully_result = \
                    "%s can not get" % self.xpath
                log.info(self.cases_actully_result)
                log.info(self.fail_print)
        else:
            log.info("There is no expect value stored")
            log.info(self.fail_print)  
            self.case_result = "FAIL"  
            
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "store_value" action: 
    #  1. Get the value by xpath.
    #  2. Store the value into local var_dict(test_data["local_var"]) by the var_name in val.
    #  If the value got store successfully  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    def store_value(self):
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("%s actual value = %s" % (self.xpath, value_list))
        self.cases_expected_result = "Store Successful" 
           
        patt_get = re.compile('\$([^ ]+)\$')
        var_list = re.findall(patt_get, self.val)
        if len(value_list) == 1:
            if len(var_list) == 1:              
                self.test_data["local_var"][var_list[0]] = value_list[0]
                log.info("%s value get suceesfully: %s" % (self.xpath,value_list[0]))
                self.cases_actully_result =  "Store Successful"      
                log.info(self.pass_print)  
                self.case_result = "PASS" 
                
            else:
                log.info("can not store values, please check the data_file")
                self.cases_actully_result = "can not store values, please check the data_file"
                log.info(self.fail_print)  
                self.case_result = "FAIL"                                         
        elif len(value_list) > 1:
            log.info("%s got too many values, please check the xpath" %self. xpath)
            log.info(self.fail_print)  
            self.cases_actully_result = "Too many values, Fail"
            self.case_result = "FAIL"  
                     
        else:
            log.info("%s can not get any value" % self.xpath)
            self.cases_actully_result = "Can not get value, Fail"
            log.info(self.fail_print)  
            self.case_result = "FAIL"
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict

    #################################################################################
    #  Start to handle the "store_value_global" action: 
    #  1. Get the value by xpath.
    #  2. Store the value into global var_dict(test_data["global_var"]) by the var_name in val.
    #  If the value got store successfully  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    def store_value_global(self):
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("%s actual value = %s" % (self.xpath, value_list)) 
        self.cases_expected_result = "Store Successful"            
        patt_get = re.compile('\$([^ ]+)\$')
        var_list = re.findall(patt_get, self.val)
        if len(value_list) == 1:
            if len(var_list) == 1:              
                self.test_data["global_var"][var_list[0]] = value_list[0]
                log.info("%s value get suceesfully: %s" % (self.xpath,value_list[0]))
                log.info(self.pass_print)  
                self.cases_actully_result =  "Store Successful"  
                self.case_result = "PASS" 
            else:
                log.info("can not store values, please check the data_file")
                log.info(self.fail_print)
                self.cases_actully_result = "can not store values, please check the data_file"
                self.case_result = "FAIL"                      
        elif len(value_list) > 1:
            log.info("%s got too many values, please check the xpath" % self.xpath)
            log.info(self.fail_print)
            self.cases_actully_result = "Too many values"  
            self.case_result = "FAIL"               
        else:
            log.info("%s can not get any value" % self.xpath)
            self.cases_actully_result = "Can not get value"
            log.info(self.fail_print)  
            self.case_result = "FAIL"
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "out_range" action: 
    #  Get the value by xpath.
    #  If the value out of the range defined by val  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    
    def out_range(self):
        log.info("Start to check value is not in the given range")
        value_list = self.tree.get_show(self.xpath, self.elem)
        self.cases_expected_result = " Not in range (%s, %s)" % (self.val[0], self.val[1])
        log.info("%s actual value = %s, range = %s" % (self.xpath, value_list, (self.val[0], self.val[1])))
        for value in value_list:
            if value in range(self.val[0], self.val[1]):
                log.info("Check failure: %s should be not in range %s" %(self.xpath, (self.val[0], self.val[1])))
                log.info(self.fail_print)
                self.cases_actully_result = "%s in range %s" % (value, (self.val[0], self.val[1])) 
                self.case_result = "FAIL"                        
                break
            else:
                pass
        else:
            log.info("Check succeed: %s is not in range %s" %(self.xpath, (self.val[0], self.val[1])))
            self.cases_actully_result = self.cases_expected_result
            log.info(self.pass_print)  
            self.case_result = "PASS"  
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "in_range" action: 
    #  Get the value by xpath.
    #  If the value in the range defined by val  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    def in_range(self):
        log.info("Start to check value is in the given range")
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("%s actual value = %s, range = %s" % (self.xpath, value_list, (self.val[0], self.val[1])))
        self.cases_expected_result = " In range (%s, %s)" % (self.val[0], self.val[1])
        self.cases_actully_result = value_list
        for value in value_list:
            if value not in range(self.val[0], self.val[1]):
                log.info("Check failure: %s should be in range %s" %(self.xpath, (self.val[0], self.val[1])))
                self.cases_actully_result = "%s Not in range %s" % (value, (self.val[0], self.val[1])) 
                log.info(self.fail_print)  
                self.case_result = "FAIL"    
                break
            else:
                pass
        else:    
            log.info("Check succeed: %s is in range %s" %(self.xpath, (self.val[0], self.val[1])))
            
            log.info(self.pass_print)  
            self.case_result = "PASS"  
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "include_value" action: 
    #  Get the value by xpath.
    #  If the value includes val  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    def include_value(self):
        log.info("Start to check value includes the given value")
        value_list = self.tree.get_show(self.xpath, self.elem)
        log.info("%s actual value = %s, range = %s" % (self.xpath, value_list, self.val))
        self.cases_expected_result = " Includ value %s" % self.val
        self.cases_actully_result = value_list
        for value in self.val:
            if value not in value_list:
                log.info("Check failure: %s should include %s" %(self.xpath, self.val))
                log.info(self.fail_print)  
                self.case_result = "FAIL"                      
                break
            else:
                pass
        else:
            log.info("Check succeed: %s includes %s" %(self.xpath, self.val))
            log.info(self.pass_print)  
            self.case_result = "PASS"
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "calculate_value" action: 
    #  1. Get the value from var_dict(test_data).
    #  2. Calculate the value by expression("xpath" part)
    #  3. Store the calculated value into var_dict(test_data["local_var"])
    #  If the successful  --Test Pass.
    #  Else---Test Fail
    #################################################################################  
    def calculate_value(self):
        log.info("Start to calculate value according to expression")
        self.cases_expected_result = "Calculate successfully"
        self.cases_actully_result = self.cases_expected_result
        try: 
            xpath = self.xpath.replace('$', '')
            val = self.val.replace('$', '')            
            value = eval(xpath, self.test_data["global_var"],self.test_data["local_var"])
            self.test_data["local_var"][val] = value
            log.info("calculate succeed: %s will store locally as %s" % (value, val))
            log.info(self.pass_print)  
            self.case_result = "PASS" 
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            log.info("calculate failure: %s can not calculate to %s" % (value, val))
            log.info(self.fail_print) 
            self.cases_actully_result = "Calculate Fail"
            self.case_result = "FAIL" 
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict    

    #################################################################################
    #  Start to handle the "calculate_value_global" action: 
    #  1. Get the value from var_dict(test_data).
    #  2. Calculate the value by expression("xpath" part)
    #  3. Store the calculated value into var_dict(test_data["global_var"])
    #  If the successful  --Test Pass.
    #  Else---Test Fail
    ################################################################################# 
    def calculate_value_global(self):
        self.cases_expected_result = "Calculate successfully"
        self.cases_actully_result = self.cases_expected_result
        try:
            log.info("Start to calculate value according to expression")
            xpath = self.xpath.replace('$', '')
            val = self.val.replace('$', '')            
            value = eval(xpath, self.test_data["global_var"],self.test_data["local_var"])
            self.test_data["global_var"][val] = value
            log.info("calculate succeed: %s will store globally as %s" % (value, val))
            log.info(self.pass_print)  
            self.case_result = "PASS" 
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            log.info("calculate failure: %s can not calculate to %s" % (value, val))
            log.info(self.fail_print) 
            self.cases_actully_result = "Calculate Fail" 
            self.case_result = "FAIL"
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict   
    #################################################################################
    #  Start to handle the "value_not_include" action: 
    #  1. Get the value by xpath.
    #  2. search in the value to check if the value contains the given string
    #  
    #  If Not include successful  --Test Pass.
    #  Else---Test Fail
    ################################################################################# 
    def value_not_include(self):
        
        log.info("Start to check value includes the given data_value")
        value_list = self.tree.get_value(self.xpath, self.elem)
        log.info("%s actual value = %s, range = %s" % (self.xpath, value_list, self.val))
        self.cases_expected_result = " Not Include bits %s" % self.val
        self.cases_actully_result = value_list
        for value in value_list:
            if re.search(self.val, value):
                log.info("Check failure: %s should Not include %s" %(self.xpath, self.val))
                log.info(self.fail_print)  
                self.case_result = "FAIL"                      
                break
            else:
                pass
        else:
            log.info("Check succeed: %s Not includes %s" %(self.xpath, self.val))
            log.info(self.pass_print)  
            self.case_result = "PASS"
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict
    
    #################################################################################
    #  Start to handle the "Check TLV" action: 
    #  1. Get the value and lengh from TLV in config.yaml file.
    #  2. check the value and length with expected express
    #  
    #  If match  --Test Pass.
    #  Else---Test Fail
    #################################################################################
    def check_tlv(self):
        log.info("Start to check the tlv by expression")
        self.cases_expected_result = self.val
        tlv_data = self.test_data["global_var"]['captureTLV']
      
        tlv_type = self.xpath
    
        try: 
            if tlv_type in tlv_data.keys():
                tlv_length = str(tlv_data[tlv_type]["length"])
                tlv_value = str(tlv_data[tlv_type]["value"])
                self.cases_actully_result = "length: %s, value: %s" % (tlv_length,tlv_value)
                log.info("actully results are %s" % self.cases_actully_result)
                log.info("expected results are %s" % self.cases_expected_result)
                length_express = 'True'
                value_express = 'True'
                check_status = True
                for key in self.val:
                    key = convert_str(key, self.test_data)
                    if re.search("length", key):
                        length_express = key.replace('length', tlv_length)
                        
                    elif re.search("value", key):
                        value_express = key.replace('value', tlv_value)
                        
                    else:
                        log.info("The exepect express do not correctly formated, please check the data file")
                        self.cases_actully_result = "The exepect express do not correctly formated, please check the data file"
                        self.case_result = "ERROR"
                        check_status = False
                        break
                if check_status:
                    
                    length_compare = eval(length_express)
                    value_compare = eval(value_express)
                    if length_compare and value_compare:  
                        log.info("TLV compare successful: length and value are expected" )
                        log.info(self.pass_print)
                        self.case_result = "PASS" 
                    else:
                        log.info("TLV compare fail: length and value are NOT expected") 
                        log.info(self.fail_print)  
                        self.case_result = "FAIL" 
            else:
                log.info("TLV compare fail: There is no TLV stored in config.yaml") 
                log.info(self.fail_print)
                self.cases_actully_result = "TLV compare fail: There is no TLV stored in config.yaml"
                self.case_result = "FAIL" 
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            log.info(self.fail_print) 
            self.cases_actully_result = "Case execute error: %s" % str(e)
            self.case_result = "ERROR" 
            
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict   
    #################################################################################
    #  Start to handle the "Store TLV" action: 
    #  1. Get the value and lengh from TLV in config.yaml file.
    #  2. check the value and length with expected express
    #  
    #  If match  --Test Pass.
    #  Else---Test Fail
    ################################################################################# 
    def store_tlv_value(self):
        log.info("Start to Store the tlv by expression")
        self.cases_expected_result = "Store TLV successfully"
        tlv_data = self.test_data["global_var"]['captureTLV']
        patt_get = re.compile('\$([^ ]+)\$')
        var_list = re.findall(patt_get, self.val)
        tlv_type = self.xpath
    
        try: 
            if tlv_type in tlv_data.keys():
                tlv_length = str(tlv_data[tlv_type]["length"])
                tlv_value = str(tlv_data[tlv_type]["value"])
                self.cases_actully_result = "length: %s, value: %s" % (tlv_length,tlv_value)
                log.info("actully results are %s" % self.cases_actully_result)
                if len(var_list) == 1:              
                    self.test_data["global_var"][var_list[0]] = tlv_value
                    log.info("TLV %s value store suceesfully: %s" % (var_list[0],tlv_value))
                    log.info(self.pass_print) 
                    self.case_result = "PASS" 
                else:
                    log.info("can not store values, please check the data_file")
                    log.info(self.fail_print)
                    self.cases_actully_result = "can not store values, please check the data_file"
                    self.case_result = "FAIL"  
                
            else:
                log.info("TLV compare fail: There is no TLV stored in config.yaml") 
                log.info(self.fail_print) 
                self.cases_actully_result =  "TLV compare fail: There is no TLV stored in config.yaml"
                self.case_result = "FAIL" 
        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            
            log.info(self.fail_print) 
            
            self.case_result = "ERROR" 
            self.cases_actully_result = "Case execute error: %s" % str(e)
        self.cases_results_dict = self._case_dict_generate()
        
        return self.cases_results_dict    
    #################################################################################
    #  Internal Method to store case related infomation in to result dict 
    ################################################################################# 
        
    def _case_dict_generate(self):
        self.cases_results_dict[self.case_number]["case_expected_result"] = self.cases_expected_result
        self.cases_results_dict[self.case_number]["case_actully_result"] = self.cases_actully_result 
        self.cases_results_dict[self.case_number]["case_info"] = self.case_info       
        
        self.cases_results_dict[self.case_number]["result"] = self.case_result
        if self.case_result == "PASS":
            self.test_data["global_var"][self.case_number] = True
        else:
            self.test_data["global_var"][self.case_number] = False
        return self.cases_results_dict
 
 
            

if __name__ == '__main__':
    
    test_path = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(test_path, 'config')
    logging_config_file = os.path.join(config_path,'logging.ini')
    logging.config.fileConfig(logging_config_file, disable_existing_loggers=False)
    data_path = os.path.join(test_path, 'data')
    pcap_file_path = os.path.join(test_path, 'original_pcap')
    source_pcap_filename = "./original_pcap/rpd_boot.pcap"
    target_pcap_file = "./filtered_pkg/test.pcap"
    target_xml_file = "./filtered_pkg/test.xml"
    pcap_file_path = os.path.join(test_path, 'original_pcap')
    filtered_file_path = os.path.join(test_path, 'filtered_pkg') 
    procedure_data_file = "./test.yaml"
    a = Procedure_run(procedure_data_file,{"test_result":"PASS", "global_var":{}, "local_var":{}},filtered_file_path, pcap_file_path)
    a.procedureExecution()
    
    
    
