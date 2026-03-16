import os
import subprocess

def run(cmd):
    os.popen(cmd)

def run2(cmd):
    subprocess.run(cmd, shell=True)