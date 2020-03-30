from stix2 import FileSystemSource
fs = FileSystemSource('./cti/enterprise-attack')

from stix2 import Filter
filt = Filter('type', '=', 'attack-pattern')

malwares = fs.query(Filter("type", "=", 'malware'))
[print(m) for m in malwares if m.name == 'Emotet']
# print(malwares[3].name)

# * Query relationships
all_rs = fs.query(Filter("type", "=", 'relationship'))
# print(all_rs[3])
relationships = [r for r in all_rs if r.source_ref == 'malware--32066e94-3112-48ca-b9eb-ba2b59d2f023']
print(relationships)
# print(type(relationships))

# * Query relationships
# all_rs = fs.query(Filter("type", "=", 'relationship'))
# [print(r) for r in all_rs if r.target_ref == 'malware--32066e94-3112-48ca-b9eb-ba2b59d2f023']

# * Query techniques
# techniques = fs.query([filt])
# print(techniques[0].x_mitre_data_sources)
# [print(t) for t in techniques]

# * Query software
# from itertools import chain

# def get_all_software(src):
#     filts = [
#         [Filter('type', '=', 'malware')],
#         [Filter('type', '=', 'tool')]
#     ]
#     return list(chain.from_iterable(
#         src.query(f) for f in filts
#     ))
    
# l = get_all_software(fs)
# print(l[0])