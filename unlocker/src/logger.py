import datetime

def log(string):
    line = "[{}] {}".format(datetime.datetime.now().replace(microsecond=0), string)
    print(line)

    with open("bypass_utility.log", "a") as out:
        out.write(line + "\n")
