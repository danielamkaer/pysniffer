import sys
import pysniffer.core

if __name__ == "__main__":
    app = pysniffer.core.Application(sys.argv)
    app.run()
