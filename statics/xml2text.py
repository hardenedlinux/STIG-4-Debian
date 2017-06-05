import sys
from lxml import etree
ns = {"xmlns": "http://checklists.nist.gov/xccdf/1.1"}
xml = etree.parse('U_Red_Hat_Enterprise_Linux_7_STIG_V1R1_Manual-xccdf.xml')

for rules in xml.xpath('//xmlns:Benchmark/xmlns:Group/xmlns:Rule[@id]',namespaces=ns):
    print "Rule ID: %s" % rules.attrib["id"]
    print "Severity: %s" % rules.attrib["severity"]
    for title in rules.findall("{http://checklists.nist.gov/xccdf/1.1}title"):
        print "Rule Title: %s" % title.text
    for description in rules.findall('.//xmlns:description',namespaces=ns):
        sys.stdout.write('Description: ')
        print description.xpath("./text()")
    for checkcontent in rules.findall(".//xmlns:check-content",namespaces=ns):
        sys.stdout.write('Check_content: ')
        print checkcontent.xpath("./text()")
    for fixtext in rules.findall(".//xmlns:fixtext",namespaces=ns):
        sys.stdout.write('Fixtext: ')
        print fixtext.xpath("./text()")
    print ""

#rules=xml.xpath('//xmlns:Benchmark/xmlns:Group/xmlns:Rule/xmlns:fixtext/text()',namespaces=ns)
#for i in enumerate(rules):
#    print i
