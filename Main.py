import untangle
import os
import subprocess
import datetime
import re
from LatexTemplate import *
from xml.sax._exceptions import SAXParseException
from pycvesearch import CVESearch


def main():
    cve = CVESearch() # Beginning the PyCVESearch api search
    latex_script_string = ""
    latex_ip_table_string = ""
    latex_devices_table_string = ""
    latex_cve_table = ""
    cve_severity_average = 0
    cve_severity_average_counter = 0
    cve_severity_low_total = 0
    cve_severity_medium_total = 0
    cve_severity_high_total = 0
    cve_severity_critical_total = 0
    latex_technical_specifics = ""
    latex_technical_specifics_vulnerable_configs_column_count = 1
    time_now = datetime.datetime.now()
    formatted_time = time_now.strftime("%Y-%m-%d %H:%M")  # Get the time and date for filenames

    scan_question = input(time_now.strftime("%H:%M") + " Do you have an IP to scan ? (Y/N): ")  # If user wishes to run a simple NMAP scan , if not they can use an existing results file
    if scan_question == "Y" or scan_question == "y":
        scan_ip = input(time_now.strftime("%H:%M") + " Enter IP Address to be scanned: ")  # Enter IP address for scan
        nmap_process = subprocess.Popen(['nmap', '-v', '-sV', '--script', 'nmap-vulners', '-oX', formatted_time + '.xml', scan_ip])  # Run the NMAP scan
        nmap_output = nmap_process.communicate()
        results_file = formatted_time + '.xml'  # Grabs result file created from NMAP scan
    else:
        file_extension_check_loop = True
        while file_extension_check_loop:  # loop to make sure an existing file is used
            results_file = input(time_now.strftime("%H:%M") + " Enter NMAP output .xml file name: ") # Input .xml file name with or without .xml file extension
            file_extension_check = results_file[-4:] # Checks if .xml file extension was added
            if file_extension_check != ".xml": # Adds .xml to end of input if not
                results_file = results_file + ".xml"
            try:
                file_exist_check = open(results_file, "r")  # Checking if file exists
                file_extension_check_loop = False
            except FileNotFoundError:
                print(time_now.strftime("%H:%M") + " ERROR: File not found please input an existing NMAP .xml output file")  # File doesnt exist, loops back
    latex_title_input = input(time_now.strftime("%H:%M") + " Please enter organisation title: ")
    try:  # Testing the file is readable
        untangle_object = untangle.parse(results_file)  # Object file created from .xml results
    except SAXParseException:
        print(time_now.strftime("%H:%M") + " ERROR: File unreadable")
        exit()
    untangle_object_scan_start_time = untangle_object.nmaprun["startstr"]
    untangle_object_scan_finish_time = untangle_object.nmaprun.runstats.finished["timestr"]
    untangle_object_hosts = untangle_object.nmaprun.host
    for untangle_object_host in untangle_object_hosts:  # Looping through the hosts in NMAP output
        untangle_object_host_address_ip = ""
        untangle_object_combined_ports = ""
        untangle_object_combined_devices = ""
        latex_technical_specifics_combined = ""
        cve_severity_low = 0
        cve_severity_medium = 0
        cve_severity_high = 0
        cve_severity_critical = 0
        cve_severity_total = 0
        for untangle_object_host_addresstype in untangle_object_host.address:
            if untangle_object_host_addresstype["addrtype"] == "ipv4":  # Parses out only the ipv4 address, stops crashes with mac address
                untangle_object_host_address_ip = untangle_object_host_addresstype["addr"]
                print(time_now.strftime("%H:%M") + " PARSING: IP Address: {}".format(untangle_object_host_address_ip))

        try:  # Testing untangle_object_host_addresstypeif the NMAP  has performed OS detection or not
            untangle_object_vendors = set()
            untangle_object_osmatch_iterator = untangle_object_host.os.osmatch
            for untangle_object_osmatch in untangle_object_osmatch_iterator:  # Looping through fingerprinted OS for each host
                untangle_object_device = untangle_object_osmatch["name"]
                print(time_now.strftime("%H:%M") + "    Device: {}".format(untangle_object_device))
                untangle_object_osclass_iterator = untangle_object_osmatch.osclass
                for untangle_object_osclass in untangle_object_osclass_iterator:
                    untangle_object_vendor = untangle_object_osclass["vendor"]
                    if untangle_object_vendor is not None:
                        untangle_object_vendors.add(untangle_object_vendor)
            print(time_now.strftime("%H:%M") + " PARSING: OS Vendors: {}".format(untangle_object_vendors))
            for vendor in untangle_object_vendors:
                untangle_object_combined_devices = untangle_object_combined_devices + vendor + " "
        except AttributeError as e:
            print(time_now.strftime("%H:%M") + " ERROR: No OS fingerprinting detected")
            untangle_object_combined_devices = untangle_object_combined_devices + "No OS identified" + " "
        latex_cve_table = latex_cve_table + "\subsection{Critical and high CVE details of host: " + untangle_object_host_address_ip + "}"  # Begins string of CVE table for current port
        untangle_object_ports = untangle_object_host.ports.port
        for untangle_object_port in untangle_object_ports:  # Looping through all open ports discovered for each host
            untangle_object_combined_scriptoutput = ""
            untangle_object_combined_cve = ""
            print(time_now.strftime("%H:%M") + " PARSING: Port: {}".format(untangle_object_port["portid"]))
            try:
                untangle_object_scripts = untangle_object_port.script
                for untangle_object_script in untangle_object_scripts:  # Looping through each script on the current port
                    untangle_object_cve_regex = re.findall(r"(CVE-\d*-\d*)\t*(\d*.\d)\t*(https:\/\/vulners.com\/cve\/CVE-\d*-\d*)", untangle_object_script["output"], flags=re.MULTILINE)  # Using Regex to search for the CVE, its severity and URL from the nmap-vulners script
                    if untangle_object_script["id"] == "vulners":  # CVE information will only be pulled out for scripts that were run by nmap-vulners
                        for untangle_object_cve in untangle_object_cve_regex:
                            latex_technical_specifics_summary = ""
                            latex_technical_specifics_vulnerable_configs = ""
                            latex_technical_specifics_references = ""
                            latex_technical_specifics_cve_cwe_cvss_table = ""
                            cve_severity_average = cve_severity_average + float(untangle_object_cve[1])  # Calculations for average severity score from each CVE
                            cve_severity_average_counter = cve_severity_average_counter + 1
                            cve_search_api = cve.id(untangle_object_cve[0])  # Using PyCVESearch to search the API for current CVE
                            if "id" in cve_search_api:
                                print(time_now.strftime("%H:%M") + " API SEARCH: CVE ID: " + cve_search_api["id"])
                                latex_technical_specifics_cve_cwe_cvss_table = "\\begin{center}\scalebox{1.5}{\\begin{tabular}{lr}\hline\multicolumn{2}{c}{" + cve_search_api["id"] + " Information} \\\\"
                            else:
                                print(time_now.strftime("%H:%M") + " ERROR: No CVE ID available")
                            if "summary" in cve_search_api:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Summary: " + cve_search_api["summary"])
                                latex_technical_specifics_summary = latex_technical_specifics_summary + "\paragraph{Summary} \mbox{} \\\\" + "\n" + "\\detokenize{" + cve_search_api["summary"] + "}"
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_summary
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: Summary: No information available")
                                latex_technical_specifics_summary = latex_technical_specifics_summary + "\paragraph{Summary} \mbox{} \\\\" + "\n" + "Information unavailable" + "}"
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_summary
                            if "cvss" in cve_search_api:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: CVSS Score: " + str(cve_search_api["cvss"]))
                                latex_technical_specifics_cve_cwe_cvss_table = latex_technical_specifics_cve_cwe_cvss_table + "\hline CVSS Score & " + str(cve_search_api["cvss"]) + "\\\\CWE & "
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: CVSS Score: No information available")
                            if "cwe" in cve_search_api:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: CWE: " + cve_search_api["cwe"])
                                latex_technical_specifics_cve_cwe_cvss_table = latex_technical_specifics_cve_cwe_cvss_table + cve_search_api["cwe"] + "\\\\\hline"
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: CWE: No information available")
                            if "impact" in cve_search_api:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Confidentiality impact: " + cve_search_api["impact"]["confidentiality"])
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Integrity impact: " + cve_search_api["impact"]["integrity"])
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Availability impact: " + cve_search_api["impact"]["availability"])
                                latex_technical_specifics_cve_cwe_cvss_table = latex_technical_specifics_cve_cwe_cvss_table + " Vulnerability impact \\\\\hline Confidentiality & " + cve_search_api["impact"]["confidentiality"] + "\\\\Integrity & " + cve_search_api["impact"]["integrity"] + "\\\\Availability & " + cve_search_api["impact"]["availability"] + "\\\\\hline"
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: Impact: No information available")
                            if "access" in cve_search_api:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Acess authentication: " + cve_search_api["access"]["authentication"])
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Access complexity: " + cve_search_api["access"]["complexity"])
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH: Access vector: " + cve_search_api["access"]["vector"])
                                latex_technical_specifics_cve_cwe_cvss_table = latex_technical_specifics_cve_cwe_cvss_table + "  Access methodology information \\\\\hline Vector & " + cve_search_api["access"]["vector"] + "\\\\Complexity & " + cve_search_api["access"]["complexity"] + "\\\\Authentication & \detokenize{" + cve_search_api["access"]["authentication"] + "}\\\\\hline"
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: Access: No information available")
                            latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_cve_cwe_cvss_table + "\end{tabular}}\end{center}"
                            if "vulnerable_configuration" in cve_search_api:
                                latex_technical_specifics_vulnerable_configs = latex_technical_specifics_vulnerable_configs + "\\begin{tiny}\\begin{spacing}{1.0} \n \paragraph{Vulnerable configs} \mbox{} \\\\" +"\n"
                                for vulnerable_config in cve_search_api["vulnerable_configuration"]:
                                    latex_technical_specifics_vulnerable_configs = latex_technical_specifics_vulnerable_configs + "\\detokenize{" + vulnerable_config["title"] + "}" + " \hfill "
                                    if latex_technical_specifics_vulnerable_configs_column_count % 3 == 0:  # This creates 3 columns of the vulnerable configurations to save room
                                        latex_technical_specifics_vulnerable_configs = latex_technical_specifics_vulnerable_configs + r'''\par\noindent'''
                                    latex_technical_specifics_vulnerable_configs_column_count = latex_technical_specifics_vulnerable_configs_column_count + 1
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_vulnerable_configs + r'''\\\\''' + "\\end{spacing}" + "\\end{tiny}"
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR: Vulnerable configurations: No information available")
                                latex_technical_specifics_vulnerable_configs = latex_technical_specifics_vulnerable_configs + "\paragraph{Vulnerable configs} \mbox{} \\\\" + "No information available"
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_vulnerable_configs
                            if "references" in cve_search_api:
                                latex_technical_specifics_references = latex_technical_specifics_references + "\paragraph{References} \mbox{} \\\\"
                                for reference in cve_search_api["references"]:
                                    latex_technical_specifics_references = latex_technical_specifics_references + "\href{" + reference + "}{\\detokenize{" + reference + "}} \\\\"
                                latex_technical_specifics_references_nopercent = re.sub(r"%", "\%", latex_technical_specifics_references)
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_references_nopercent + r'''\\\\'''
                            else:
                                print(time_now.strftime("%H:%M ") + cve_search_api["id"] + " API SEARCH ERROR:  References: No information available")
                                latex_technical_specifics_references = latex_technical_specifics_references + "\paragraph{References} \mbox{} \\\\" + "No information available"
                                latex_technical_specifics_combined = latex_technical_specifics_combined + latex_technical_specifics_references
                            latex_technical_specifics_combined = latex_technical_specifics_combined + "\\newpage"  # Completes the report page for current CVE
                            cve_severity = float(untangle_object_cve[1])
                            if cve_severity <= 3: # Determines the colour of severity cell in CVE table
                                cve_severity_low = cve_severity_low + 1
                                cve_severity_total = cve_severity_total + 1
                                cve_severity_low_total = cve_severity_low_total + 1
                            else:
                                if cve_severity >3 and cve_severity <= 6:
                                    cve_severity_medium = cve_severity_medium + 1
                                    cve_severity_total = cve_severity_total + 1
                                    cve_severity_medium_total = cve_severity_medium_total + 1
                                else:
                                    if cve_severity > 6 and cve_severity < 9:
                                        cve_severity_total = cve_severity_total + 1
                                        cve_severity_high = cve_severity_high + 1
                                        cve_severity_high_total = cve_severity_high_total + 1
                                    else:
                                        if cve_severity >= 9:
                                            cve_severity_total = cve_severity_total + 1
                                            cve_severity_critical = cve_severity_critical + 1
                                            cve_severity_critical_total = cve_severity_critical_total + 1
                        latex_cve_table = latex_cve_table + re.sub(r"(REGEXCVETABLEREGEX)", untangle_object_combined_cve, latex_template_cve_table, count=0, flags=0)  # Creating the table string from table template
                        latex_cve_table = re.sub(r"(REGEXPORTHERE)", untangle_object_port["portid"], latex_cve_table, count=0, flags=0)
                    untangle_object_combined_scriptoutput = untangle_object_combined_scriptoutput + " NMAP Script run: " + untangle_object_script["id"] + " NMAP Script Result: " + untangle_object_script["output"]  # Creating a string of the raw scripts information of every script run
            except AttributeError as e:
                print(time_now.strftime("%H:%M") + " ERROR: No scripts detected")
            untangle_object_combined_ports = untangle_object_combined_ports + untangle_object_port["portid"] + " "  # Creating a combined string of each host and its discovered ports
            latex_script_string = latex_script_string + untangle_object_combined_scriptoutput + "\n"  # Creating a LaTeX string from template file and combined script string
        latex_technical_specifics = latex_technical_specifics + "\\newpage\subsection{Vulnerability details of host: " + untangle_object_host_address_ip + "}"  # Begins string of CVE table for current port
        latex_technical_specifics_perhost_severity_string = "Critical\cellcolor{red}&\cellcolor{red} " + str(cve_severity_critical) + r'\\\\' + "High\cellcolor{orange}&\cellcolor{orange}" + str(cve_severity_high) + r'''\\\\''' + "Medium\cellcolor{yellow}&\cellcolor{yellow}" + str(cve_severity_medium) + r'''\\\\''' + "Low \cellcolor{green}&\cellcolor{green}" + str(cve_severity_low) + r'''\\\\\hline Total& ''' + str(cve_severity_total)
        latex_technical_specifics_perhost_severity = re.sub(r"(REGEXPERHOSTSEVERITYREGEX)", latex_technical_specifics_perhost_severity_string, latex_template_technical_specifics_perhost_severity, count=0, flags=0)
        latex_technical_specifics = latex_technical_specifics + latex_technical_specifics_perhost_severity + latex_technical_specifics_combined
        latex_cve_table = latex_cve_table + r'''\newpage'''
        latex_devices_table_string = latex_devices_table_string + untangle_object_host_address_ip + "&" + untangle_object_combined_devices + r'''\\\\'''  # Creating a LaTeX table string from template file and combined devices string
        latex_ip_table_string = latex_ip_table_string + untangle_object_host_address_ip + " & " + untangle_object_combined_ports + "&" + untangle_object_combined_devices + r'''\\\\'''  # Creating a LaTeX table string from template file and combined ports string
    latex_ip_table_string = latex_ip_table_string + "\hline Scan start time & " + untangle_object_scan_start_time + r'\\\\' + "Scan end time & " + untangle_object_scan_finish_time + r'\\\\'
    cve_severity_average = cve_severity_average / cve_severity_average_counter  # Finishing calculation of severity average
    latex_title = re.sub(r"(REGEXTITLEHEREREGEX)", latex_title_input, latex_template_title, count=0, flags=0)  # Using Regex to replace the placeholder title in title LaTeX template
    latex_executive_summary = re.sub(r"(REGEXTITLEHEREREGEX)", latex_title_input, latex_template_executive_summary, count=0, flags=0)  # Using Regex to replace the placeholder title in executive summary LaTeX template
    if cve_severity_average == 0:  # Determines what executive summary is chosen, determined by the average severity score
        latex_executive_summary = re.sub(r"(REGEXRISKSTATEMENTREGEX)", latex_template_executive_summary_risk_none, latex_executive_summary, count=0, flags=0)
    else:
        if cve_severity_average >0 and cve_severity_average<= 3:
            latex_executive_summary = re.sub(r"(REGEXRISKSTATEMENTREGEX)", latex_template_executive_summary_risk_low, latex_executive_summary, count=0, flags=0)
        else:
            if cve_severity_average > 3 and cve_severity_average <= 6:
                latex_executive_summary = re.sub(r"(REGEXRISKSTATEMENTREGEX)", latex_template_executive_summary_risk_medium, latex_executive_summary, count=0, flags=0)
            else:
                if cve_severity_average > 6:
                    latex_executive_summary = re.sub(r"(REGEXRISKSTATEMENTREGEX)", latex_template_executive_summary_risk_high, latex_executive_summary, count=0, flags=0)
    latex_overall_severity_results_string = "Critical\cellcolor{red}&\cellcolor{red} " + str(cve_severity_critical_total) + r'\\\\' + "High\cellcolor{orange}&\cellcolor{orange}" + str(cve_severity_high_total) + r'''\\\\''' + "Medium\cellcolor{yellow}&\cellcolor{yellow}" + str(cve_severity_medium_total) + r'''\\\\''' + "Low \cellcolor{green}&\cellcolor{green}" + str(cve_severity_low_total) + r'''\\\\\hline Total& ''' + str(cve_severity_average_counter)
    latex_overall_severity_results = re.sub(r"(REGEXSEVERITYOVERALLHEREREGEX)", latex_overall_severity_results_string, latex_template_technical_specifics_overall_severity_results, count=0, flags=0)
    latex_results_table = re.sub(r"(REGEXIPPORTTABLEHEREREGEX)", latex_ip_table_string, latex_template_results_table, count=0, flags=0)  # Using Regex to replace the placeholder table in results table LaTeX template with the host and ports
    latex_raw_results = re.sub(r"(REGEXSCRIPTSTUFFREGEX)", latex_script_string, latex_template_raw_results, count=0, flags=0)  # Using Regex to replace the raw scripts placeholder in LateX template
    file_latex = open(latex_title_input + 'GeneratedReport.tex', "w+")  # Creating the LaTeX .tex file
    latex_template = latex_template_packages + latex_title + latex_executive_summary + latex_template_technical_specifics + latex_results_table + latex_overall_severity_results + latex_technical_specifics + latex_raw_results  # Combining the LaTeX template strings to create the entire template
    file_latex.write(latex_template)  # Writing the LaTeX template to the .tex file
    file_latex.close()
    pdflatex_process = subprocess.Popen(['pdflatex', latex_title_input + 'GeneratedReport.tex'])  # Generate PDF report from LaTex .tex file (LaTeX only produces contents file on second report generation)
    pdflatex_process.communicate()
    pdflatex_process = subprocess.Popen(['pdflatex', latex_title_input + 'GeneratedReport.tex'])  # Run a second time as pdfLatex produces contents .toc file after starting pdf generation
    pdflatex_process.communicate()


if __name__ == "__main__":
    main()



