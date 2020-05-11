

class BigDict(object):

    def __init__(self):
        self.collection = dict()

    def put(self, key, value):
        if self.collection.__contains__(key):
            old = self.collection.get(key)
            self.collection[key] = old + ',' + value
        else:
            self.collection[key] = value

    def keys(self):
        return self.collection.keys()

    def get(self, key):
        return self.collection[key]

    def pop(self, key):
        return self.collection.pop(key)
