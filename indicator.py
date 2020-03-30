from stix2 import Indicator

indicator = Indicator(name="File hash for malware variant",
                      labels=["malicious-activity"],
                      pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")
# print(indicator)
print(type(indicator))

from stix2 import parse

indicator1 = parse("""{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
    "created": "2017-09-26T23:33:39.829Z",
    "modified": "2017-09-26T23:33:39.829Z",
    "name": "File hash for malware variant",
    "indicator_types": [
        "malicious-activity"
    ],
    "pattern_type": "stix",
    "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
    "valid_from": "2017-09-26T23:33:39.829952Z"
}""")
# print(indicator1)
print(type(indicator1))


indicator2 = parse(indicator)
print(indicator2)



# "attack-pattern--00d0b012-8a03-410e-95de-5826bf542de6": {
#     "description": "If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.\n\nA good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use [Software Packing](https://attack.mitre.org/techniques/T1045) or otherwise modify the file so it has a different signature, and then re-use the malware.",
#     "example_uses": [
#       "The author of  submitted samples to VirusTotal for testing, showing that the author modified the code to try to hide the DDE object in a different part of the document.",
#       "apparently altered  samples by adding four bytes of random letters in a likely attempt to change the file hashes.",
#       "Find-AVSignature AntivirusBypass module can be used to locate single byte anti-virus signatures.",
#       "has been known to remove indicators of compromise from tools.",
#       "Analysis of  has shown that it regularly undergoes technical improvements to evade anti-virus detection.",
#       "Based on comparison of  versions,  made an effort to obfuscate strings in the malware that could be used as IoCs, including the mutex name and named pipe.",
#       "has tested malware samples to determine AV detection and subsequently modified the samples to ensure AV evasion.",
#       "includes a capability to modify the \"beacon\" payload to eliminate known signatures or unpacking methods.",
#       "has updated and modified its malware, resulting in different hash values that evade detection."
#     ],
#     "id": "T1066",
#     "name": "Indicator Removal from Tools",
#     "similar_words": [
#       "Indicator Removal from Tools"
#     ]
#   }