


try:
    import sys, os
    import logging
    import logging.config
    import traceback
    import yamlordereddictloader
    import yaml
    import time
    from ATPExecution import ATP_Execution
    import pytest
    import warnings
    
except ImportError as e:
    raise ImportError (str(e) + """
    A critical module was not found. Probably this operating system does not
    support it. Please fix the import error before running the test.""")

test_list = []
for index in sys.argv[1:]:
    test_list.append(int(index))

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)s %(message)s')
console.setFormatter(formatter)
    
test_path = os.path.dirname(os.path.abspath(__file__))    
config_path = os.path.join(test_path, 'config') 

data_path = os.path.join(test_path, 'data')
pcap_file_path = os.path.join(test_path, 'original_pcap')
filtered_file_path = os.path.join(test_path, 'filtered_pkg')
config_file = os.path.join(config_path,'config.yaml')
ATPtest = ATP_Execution(data_path = data_path,
                       pcap_file_path = pcap_file_path,
                       filtered_file_path = filtered_file_path,
                       config_file = config_file)

procdures = ATPtest.procedureSelect(test_list)
procedure_list = []

for procedure in procdures:
    procedure_list.append(procedure)
        

@pytest.mark.parametrize(('procedure'),procedure_list)
def test_procedure(procedure,capsys):
    with capsys.disabled():
        procedure_results = ATPtest.procedureExecute(procedure)
    log = logging.getLogger(procedure)
    log.addHandler(console)
    procedure_result = procedure_results["result"]
    procedure_execute_info = procedure_results["procedure_execute_info"]
    filters = procedure_results["filters"]
    test_cases = procedure_results["cases"] 
    log.info("The procedure %s ---> %s" % (procedure,procedure_result))
    log.info("The procedure_execute_info ---> %s" % procedure_execute_info)
    log.info("Please check the detail results")
    log.info("+++++++++++Filter Results+++++++++++++")
    for key in sorted(filters):
        filter_result = filters[key]
        log.info("The filter %s " % key)
        log.info("%s" % filter_result)
        log.info("=================================")
    
    log.info("+++++++++++Cases Result++++++++++++++")
    passed_case = 0
    errored_case = 0
    failed_case = 0
    blocked_case = 0
    skiped_case = 0
    total_case = 0
    for key in sorted(test_cases):
        total_case += 1
        case_result = test_cases[key]["result"]
        if case_result == "PASS":
            passed_case += 1
        elif case_result == "FAIL":
            failed_case += 1
        elif case_result == "SKIPED":
            skiped_case += 1
        elif case_result == "BLOCKED":
            blocked_case += 1
        elif case_result == "ERROR":
            errored_case += 1
        else:
            pass
                
        case_expected_result = test_cases[key]["case_expected_result"]
        case_actully_result = test_cases[key]["case_actully_result"]
        case_info = test_cases[key]["case_info"]
        log.info("The Cases %s ----> %s" % (key, case_result))
        log.info("case: %s" % case_info)
        log.info("Expected Result ----->%s" % case_expected_result)
        log.info("Actully Result  ----->%s" % case_actully_result)
        log.info("=================================")
    log.info("============Test cases results summary==============")
    log.info("\nTotal cases Number: %s \
            \nPassed cases Number: %s \
            \nFailed cases Number: %s \
            \nSkiped Cases Number: %s \
            \nBlocked Cases Number: %s \
            \nErrored Cases Number: %s" \
            % (total_case, passed_case,failed_case,skiped_case,blocked_case,errored_case))
    
    log.debug(procedure_results)        
    assert procedure_result == "PASS"

    
if __name__ == "__main__":
    
    warnings.filterwarnings("ignore") 
    test_path = os.path.dirname(os.path.abspath(__file__))    
    
    log_path = os.path.join(test_path, 'log')
    now = time.strftime('%Y%m%d-%H%M%S')
    now_log_folder = os.path.join(log_path , now)

    if not os.path.exists(now_log_folder) :
        os.mkdir(now_log_folder)
    
    log_file_name = "atp_log_%s.log" % now
    html_file_name = "log_%s.html" % now
    
    log_file = os.path.join(now_log_folder, log_file_name)
    
    #################################################################################################
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=log_file,
                    filemode='w')
    #################################################################################################

    html_file = os.path.join(now_log_folder, html_file_name)
    
    
    html = "--html=%s" % html_file
    pytest.main([__file__, "--tb=short", html])    
    


