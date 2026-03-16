import pickle

def load_data(path):
    f = open(path,"rb")
    return pickle.load(f)