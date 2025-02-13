import gzip
import json

# Define the path to the .gz file
gz_file_path = "/home/logan/Dev/IntermediateDragon/testDirtyBin/types/00ee71237c8408bdaf6fa782d73f2cb76dbddb1883cb188e384641ee9fbea90b_libbrlttybmb.so.json.gz"

# Open and read the .gz file
with gzip.open(gz_file_path, 'rt', encoding='utf-8') as gz_file:
    # Read and parse each line as a separate JSON object
    for line in gz_file:
        json_object = json.loads(line)
        # Print the JSON object
        print(json.dumps(json_object, indent=4))
        #break