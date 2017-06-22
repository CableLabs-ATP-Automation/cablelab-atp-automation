import os, sys, re

import xml.etree.ElementTree as ET
import logging
import traceback
from decimal import *
log = logging.getLogger(__name__)



def convert_str(string, var_dict):
    '''covert one string contains variables with the value stored in variables dict.
    
    Args:
        string : the string contains variables($var_name$) need to be converted
                sample: string = "$var_1$ is a dog"
                
        var_dict: the variables dict contains variables name as key and value as value.
                    need "global_var" and "local_var" to indication the scope.
                sample: var_dict = {"global_var":{"var_1":1, "var_2":2},"local_var":{"var_3":3, "var_3":3}}
                
    Returns:
        string after convert,if such covert successful
        return None, if there is no variables found in var_dict    
    '''
    patt_get = re.compile('\$([^ ]+)\$')
    var_list = re.findall(patt_get, string)

    

    for var_name in var_list:
        
        if var_name in var_dict["local_var"]:
            if var_dict["local_var"][var_name]:
                var_value = str(var_dict["local_var"][var_name])
                patt_replace = re.compile('(\$%s\$)' % var_name)
                string = patt_replace.sub(var_value, string)
            else:
                string = None
                break
        elif var_name in var_dict["global_var"]:
            if var_dict["global_var"][var_name]:
                var_value = str(var_dict["global_var"][var_name])
                patt_replace = re.compile('(\$%s\$)' % var_name)
                string = patt_replace.sub(var_value, string)
            else:
                string = None
                break
        else:
            string = None
            break
    return string

def convert_express(express, var_dict):
    '''covert one expression contains variables with the value stored in variables dict.
    
    Args:
        express : the express contains variables($var_name$) need to be converted
                sample: express = "($var_1$ - 6)/2"
                
        var_dict: the variables dict contains variables name as key and value as value.
                    need "global_var" and "local_var" to indication the scope.
                sample: var_dict = {"global_var":{"var_1":1, "var_2":2},"local_var":{"var_3":3, "var_3":3}}
                
    Returns:
        expect_value after calculation, if such calculate successful
        return None, if there is no variables found in var_dict    
    '''
    
    
    if isinstance(express, str):
        
        express = express.replace('$', '')
        
        if express in var_dict["local_var"]:
            expect_value = eval(express, var_dict["local_var"])
        elif express in var_dict["global_var"]:
            expect_value = eval(express, var_dict["global_var"])
        else:
            expect_value = None
    else:
        expect_value = express
        
    return expect_value

def var_assign(source_dict, var_dict, mode="local"):
    '''covert all the value contains variables in the source_dict and stored the variables in variables dict.
    
    Args:
        source_dict : the dict contains variables($var_name$) need to be converted
                sample: source_dict = {"mode_1": "test with $var_1$ and $var_2$",
                                        "mode_2": "test with $var_3$ and $var_4$" }
                
        var_dict: the variables dict contains variables name as key and value as value.
                    need "global_var" and "local_var" to indication the scope.
                sample: var_dict = {"global_var":{"var_1":1, "var_2":2},
                                    "local_var":{"var_3":3, "var_3":3}}
                                    
        mode: define the variables scope, defalt value is "local"
    
    Returns:
        status: True if covert and store is OK
                False if Fail
    '''
    status = True
    for key in source_dict:

        new_string = convert_str(source_dict[key], var_dict)
        if not new_string:
            new_string = convert_express(source_dict[key], var_dict)
        else:
            pass
        if new_string:
        
            if mode == "global":
                var_dict["global_var"][key] = new_string
            elif mode == "local":
                var_dict["local_var"][key] = new_string
            else:
                pass  
        else:
            status= False
            break   
        
    return status



def test_case_analyze(string):
    '''analyze the test case string.
    
    Args:
        String: {#case_number}{case_axtion}{xpath/expression}
    
    Returns:
        case_number, case_action, xpath
    '''
    
    pattern_a = re.compile('^\{(?P<case_number>.*)\}\{(?P<case_info>.*)\}\{(?P<case_action>.*)\}\{(?P<xpath>.*)\}')
    pattern_b = re.compile('^\{(?P<case_number>.*)\}\{(?P<case_info>.*)\}\{(?P<case_action>.*)\}')
    if re.match(pattern_a,string):
        key_dict = re.match(pattern_a,string).groupdict()
        case_number = key_dict["case_number"]
        case_info = key_dict["case_info"]
        case_action = key_dict["case_action"]
        xpath = key_dict["xpath"]
    elif re.match(pattern_b,string):
        key_dict = re.match(pattern_b,string).groupdict()
        case_number = key_dict["case_number"]
        case_info = key_dict["case_info"]
        case_action = key_dict["case_action"]
        xpath = None
    else:
        case_number = None
        case_info = None
        case_action = None
        xpath = None    
    
    return case_number,case_info, case_action, xpath

def test_result_analyze(test_results):
    procedure_result = test_results["result"]
    cases = test_results["cases"]
    for case in cases:
        if procedure_result == "ERROR":
            pass
        
        elif cases[case]["result"] == "FAIL" or cases[case]["result"] == "ERROR" :
            test_results["result"] = cases[case]["result"]
            procedure_execute_info = "Procedure result is : %s, please check the details below" % test_results["result"]
            test_results["procedure_execute_info"] = procedure_execute_info
        else:
            pass
        
    return test_results

def case_result_fulfill(cases, status, reason):
    case_list = []
    cases_results_dict = {}
    for case in cases:
        case_list.append(case)
        if isinstance(cases[case], dict):
            sub_cases = cases[case]
            for sub_case in sub_cases:
                case_list.append(sub_case)
        else:
            pass
            
    for case in case_list:
        case_number, case_info, case_action, xpath = test_case_analyze(case)
        cases_results_dict[case_number] = {}
        cases_results_dict[case_number]["case_expected_result"] = "N.A."
        cases_results_dict[case_number]["case_actully_result"] = reason
        cases_results_dict[case_number]["result"] = status
        cases_results_dict[case_number]["case_info"] = case_info
        
        
    return (cases_results_dict)   

class XML_analyze():
    
    def __init__(self,xml_file):
        self.tree = ET.ElementTree(file=xml_file)

    def identify_field(self,xpath):
        filter_elem_list = []
        elem_list = self.tree.findall(xpath)
        if len(elem_list) > 0 :
            for elem in elem_list:
                filter_elem_list.append(elem)
        return filter_elem_list
        
              
    def get_show(self,xpath,elem=None):
        
        value_list = []
        if elem:
            elems_list = elem.findall(xpath) 
        else:
            elems_list = self.tree.findall(xpath)
        for elems in elems_list:
            value = elems.get("show")
            if value == '':
                value = None
            else:
                if re.match(r"0x", value):
                    value = int(value, 16)
                elif re.match(r"\d+\.\d+", value):
                    value = Decimal(value)
                else:
                    value = int(value)             
            value_list.append(value)
        return value_list
       
    def get_start_bits(self,elem):

        start_bits = bin(int(elem.get("value"), 16))
        start_bits = start_bits[0:14]
        return start_bits
    
    def get_value(self,xpath,elem=None):
        
        value_list = []
        if elem:
            elems_list = elem.findall(xpath) 
        else:
            elems_list = self.tree.findall(xpath)
        for elems in elems_list:
            value = elems.get("value")
            if value == '':
                value = None
                        
            value_list.append(value)
        return value_list
    
    def get_name(self,elem):
        
        return self.elem.get("show")
    
    def get_max(self, xpath):
        max_list = []
        value_list = self.get_show(xpath)
        max_list.append(max(value_list))
        return max_list
    
    def get_min(self, xpath):
        min_list = []
        value_list = self.get_show(xpath)
        min_list.append(min(value_list))
        return min_list
        


        
        
            
if __name__ == "__main__":
    
    xml_file = "../filtered_pkg/#9_L2TPv3_Control_messages_CCAP_to_RPD.xml"
    tree = XML_analyze(xml_file)
    #elems = tree.identify_field("//field[@name='']/field[@show='0'][@name='l2tp.avp.type']...")
    elems = tree.identify_field("//field[@show='0'][@name='l2tp.avp.type']...")
    for elem in elems:
        values = tree.get_show("field[@name='l2tp.type']", elem)
        for value in values:
            print (value)
             
    for elem in elems:
        print (tree.get_start_bits(elem))
        
    
    
    
                
            
            
                
                
            
        