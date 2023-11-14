# level: WARNING
# start_line: 15
# end_line: 15
# start_column: 18
# end_column: 30
import marshal


data = {"name": "John Doe", "age": 30}

with open("data.dat", "wb") as f:
    marshal.dump(data, f)

with open("data.dat", "rb") as f:
    loaded_data = marshal.load(f)
