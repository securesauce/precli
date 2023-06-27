import marshal


data = {"name": "John Doe", "age": 30}

with open("data.dat", "wb") as f:
    marshal.dump(data, f)

with open("data.dat", "rb") as f:
    loaded_data = marshal.load(f)
