#!/usr/local/bin/python -O

""" Tool to show BeeDict data.

"""
import cPickle,sys,os
from BeeDict import *
import CommandLine
from mx import Log

def show(name,keys,all=0,levels=3):

    print 'Records from BeeDict "%s"' % name
    print
    d = BeeDict(name,
                readonly=1)
    if all:
        keys = d.keys()
    for key in keys:
        print_record(d,key,levels)
        print
    d.close()

def print_record(d,key,levels=3):

    print 'Record for key "%s"' % str(key)[:50]
    try:
        data = d[key]
    except:
        print 'Failed to load.'
        return
    try:
        data = cPickle.loads(data)
    except:
        pass
    Log.print_obj(data,indent='  ',levels=levels)

class ShowRecord(CommandLine.Application):

    header = 'Tool for displaying BeeDict records'
    synopsis = '%s [options] dictname keys...'
    options = [CommandLine.ArgumentOption('-d','Display depth',3),
               CommandLine.SwitchOption('-a','Show all records')
               ]

    def check_files(self,files):

        if len(files) < 1:
            self.help('Missing arguments')
            sys.exit(1)

    def main(self):

        show(self.files[0],self.files[1:],self.values['-a'],self.values['-d'])

if __name__ == '__main__':
    ShowRecord()
        
