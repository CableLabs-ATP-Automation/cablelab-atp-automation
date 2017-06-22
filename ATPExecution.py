


try:
    import sys, os
    _ext_lib_path = os.path.join(os.path.dirname(__file__), 'libs')
    sys.path.append(_ext_lib_path)
    import logging
    import logging.config
    import traceback
    import yamlordereddictloader
    import yaml
    from ATPCases import Procedure_run
    from ATPComOpt import test_result_analyze
except ImportError as e:
    raise ImportError (str(e) + """
    A critical module was not found. Probably this operating system does not
    support it. Please fix the import error before running the test.""")
    
    
    
log = logging.getLogger(__name__)



class ATP_Execution():
    
    def __init__(self, **kwargs):
        self.config_file = kwargs["config_file"]
        self.filtered_file_path = kwargs["filtered_file_path"]
        self.pcap_file_path = kwargs["pcap_file_path"]
        self.data_path = kwargs["data_path"]
        self.test_procedures = []
        self.procedure_index_list = []
        try:            
            self.conf = yaml.load(open(self.config_file), Loader=yamlordereddictloader.Loader)
        
        
            self.procedure_list = self.conf["procedure"]
            for key in self.procedure_list:
  
                self.test_procedures.append(self.procedure_list[key]["name"])
                self.procedure_index_list.append(key)
                
            
            
            self.test_data = {"local_var" : {},"global_var": {}}
            self.test_data["global_var"] = self.conf['basic_config']
            self.test_data["global_var"]['captureTLV'] = self.conf['captureTLV']
            

        except Exception as e:
            traceback.print_exc()
            log.error(str(e))
            log.info("There is Error when read config_file, please check the config_file")
     
    def procedureSelect(self, test_list=None):
        log.info ("procedure select") 
        if test_list:
            
            if set(test_list).issubset(set(self.procedure_index_list)):
                for index in test_list:
                    procedure = self.procedure_list[index]["name"]
                    yield procedure
            else:
                log.info("The test_list does not contained in config_file, please check the test_list")
        
        else:    
            for procedure in self.test_procedures:
                yield procedure
            
    def procedureExecute(self, procedure_name):
        """ Common Setup subsection """
        log.info("execute procedure %s by procedure_name" % procedure_name)
        test_result = {}
        for key in self.procedure_list:
           
            if self.procedure_list[key]["name"] == procedure_name:
                procedure_data_file_name = self.procedure_list[key]["data_file"]
                procedure_data_file = os.path.join(self.data_path, procedure_data_file_name)
                self.test_data["local_var"] = {}
                test = Procedure_run(procedure_data_file, self.test_data, self.filtered_file_path, self.pcap_file_path)
                test_result = test.procedureExecution()                           
                break
        else:
            procedure_execute_info = "Can not find %s in config file" % procedure_name
            test_result["result"] = "ERROR"
            test_result["procedure_execute_info"] = procedure_execute_info
        test_result = test_result_analyze(test_result)
        log.info("procedure %s Test result is ---> %s " % (procedure_name, test_result["result"]))
        log.info("procedure_execute_info is ---> %s " % test_result["procedure_execute_info"])
        #print (test_data)
        return test_result
        
    
if __name__ == "__main__":
    
    test_path = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(test_path, 'config')
    logging_config_file = os.path.join(config_path,'logging.ini')
    logging.config.fileConfig(logging_config_file, disable_existing_loggers=False)
    data_path = os.path.join(test_path, 'data')
    pcap_file_path = os.path.join(test_path, 'original_pcap')
    filtered_file_path = os.path.join(test_path, 'filtered_pkg')
    config_file = os.path.join(config_path,'config.yaml')
    
    ATPtest = ATP_Execution(data_path = data_path,
                           pcap_file_path = pcap_file_path,
                           filtered_file_path = filtered_file_path,
                           config_file = config_file)
    
    procdures = ATPtest.procedureSelect(test_list=None)

    for procdure in procdures:
        
        log.info (ATPtest.procedureExecute(procdure)["result"])


