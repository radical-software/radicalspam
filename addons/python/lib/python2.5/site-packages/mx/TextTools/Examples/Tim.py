""" Example for dynamic programming with Tag Tables... originated from
    a posting to comp.lang.python by Tim Peters:

[Tim]
> [Marc-Andre]
> I can stick in any matching function I want, so I might even
> let re.match() do some of the work. That should get me pretty close
> to their semantics -- ok, I can't do it all the way:

Sure you can:  just let re.match() do *all* the work!  Presto, tables are as
powerful as re.

> e.g. I currently don't have registers so back-references to already
> matched groups will probably not work without reanalysing them.

So you have trouble recognizing e.g. the language of the form

   <tag> ... </tag>

where "tag" can be any (say) arbitrary alphanumeric string?  <S> <Like> this
clause is in that language </Like>, <but> this clause isn't <but/>, while
the whole sentence is -- if you ignore the trailing period </S>.  It's even
better if you can do computation on backreferences and use the results to
guide further parsing.  E.g., recognizing Fortran Hollerith strings requires
this (a string of digits, followed by "H" or "h", followed by any string of
characters whose length is equal to the decimal value of the string of
digits; and that's too hard for regexps too).

teasingly y'rs  - tim
"""
from mx.TextTools import *

tables = [None]

def opening_tag(taglist,text,l,r,subtags):
    # First append an entry to the taglist
    tagname = text[l+1:r-1]
    taglist.append(('open '+tagname,l,r,subtags))
    # Now build a tag table that searches for </tagname>
    tables[0] = ((None,sWordStart,TextSearch('</'+tagname+'>')),
                 )

def closing_tag(taglist,text,l,r,subtags):
    tagname = text[l+2:r-1]
    taglist.append(('close '+tagname,l,r,subtags))

TIM = (
    # Check starting tag
    (opening_tag,Table+CallTag,
     ((None,Is,'<'),
      (None,AllInSet,alphanumeric_set),
      (None,Is,'>'),
      )),
    # Find closing tag
    ('text',TableInList,(tables,0)),
    # For completeness mark the closing tag too
    (closing_tag,Table+CallTag,
     ((None,Word,'</'),
      (None,AllInSet,alphanumeric_set),
      (None,Is,'>'),
      )),
)

def _test():

    while 1:
        text = raw_input('Enter a string in TIM: ')
        if not text:
            break
        result,taglist,next = tag(text,TIM)
        if result:
            print 'The text you gave was recognized as TIM:'
            print_tags(text,taglist)
        else:
            print "Sorry, but the text doesn't qualify as TIM."
            print 'The search stopped at:'
            print repr(text[:next]) + '<<<'

if __name__ == '__main__':
    _test()
