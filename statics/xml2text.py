import sys
import os
from lxml import etree
ns = {"xmlns": "http://checklists.nist.gov/xccdf/1.1"}

filename="U_Red_Hat_Enterprise_Linux_7_STIG_V1R1_Manual-xccdf.xml"

if os.access("/hardenedlinux/STIG-4-Debian/statics/U_Red_Hat_Enterprise_Linux_7_STIG_V1R4_Manual-xccdf.xml", os.F_OK):
	filename="U_Red_Hat_Enterprise_Linux_7_STIG_V1R4_Manual-xccdf.xml"

#xml = etree.parse('U_Red_Hat_Enterprise_Linux_7_STIG_V1R1_Manual-xccdf.xml')
xml = etree.parse(filename)

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
