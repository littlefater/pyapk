"""
Test ZipWalker Module
"""

import os
import sys

sys.path.append(os.path.abspath(".."))
import module.zipwalker as zipwalker


if __name__ == '__main__':

    try:
        testzip = zipwalker.Zip('none.zip', True)
    except Exception as e:
        print '[!] Error: ' + str(e)
    print '-' * 40
    
    try:
        testzip = zipwalker.Zip('test.txt', True)
    except Exception as e:
        print '[!] Error: ' + str(e)
    print '-' * 40

    testzip = zipwalker.Zip('test.zip', True)
    print '-' * 40
    
    testzip = zipwalker.Zip('test_enc.zip', True)
    