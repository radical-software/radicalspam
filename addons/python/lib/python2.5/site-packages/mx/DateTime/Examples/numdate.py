# numdate.py
"""
The functions in this module are useful for data entry or bulk data
import, where dates are in an all-numeric format.  Because of the
possibility that the user might type the wrong thing in a numeric
field, or a data file might contain other data or garbage where a date
is expected, it is desirable to return None or raise an exception
when an invalid expression is encountered.

Dates can be in any of these formats: ymd, dmy, or mdy
with any single-character nondigit separator, two- or four-digit
year, and one- or two-digit month and day; or they can be in all-digits
ymd format with no separator, four-digit year, and two-digit
month and day (e.g. 20010803).

In accordance with ISO 8601, two-digit years in all-numeric dates
are interpreted as referring to the current century.

Synopsis:
    DateTime = numericDateTime(datetimestring, formats='ymd mdy dmy'))
        Return value is based on date and (if any) time data in the string.
    DateTime = numericDate(datestring, formats='ymd mdy dmy'))
        Return value is based on date data in the string.
    DateTimeDelta = numericTime(timestring)
        Return value is based on time data in the string.

20010804 JJD Created, borrowing some regular expressions and
         ideas from mxDateTime's Parser module.
20020404 JJD Fixed _THIS_CENTURY to use 100-year century (not 1000).

Donated to eGenix for mxDateTime
"""
from mx import DateTime
import re

# RE's can be simple if the dates are all-numeric
# A year, month, or day is some number of digits not preceded by
# or followed by a digit or a colon.
_year  = r'(?P<year>(?<![\d:])\d{2,4}(?![\d:]))'
_month = r'(?P<month>(?<![\d:])\d{1,2}(?![\d:]))'
_day   = r'(?P<day>(?<![\d:])\d{1,2}(?![\d:]))'
# The <sep> group is used in a way to guarantee that the same
# separator character is used twice in the date expression.
_ymd = _year  + r'(?P<sep>\D)' + _month + r'(?P=sep)' + _day + r'(?!\d)'
_dmy = _day   + r'(?P<sep>\D)' + _month + r'(?P=sep)' + _year + r'(?!\d)'
_mdy = _month + r'(?P<sep>\D)' + _day   + r'(?P=sep)' + _year + r'(?!\d)'
_ymdRE  = re.compile(_ymd,  re.I)
_dmyRE  = re.compile(_dmy,  re.I)
_mdyRE  = re.compile(_mdy,  re.I)
_formatdict = {'ymd':_ymdRE, 'dmy':_dmyRE, 'mdy':_mdyRE}

_hour = r'(?P<hour>[012]?\d)'
_minute = r'(?P<minute>[0-6]\d)'
_second = r'(?P<second>[0-6]\d(?:\.\d+)?)'
_time = _hour + r':' + _minute + r'(?::' + _second + r')?'
_timeRE = re.compile(_time, re.I)

# Use divmod to avoid Guido's evil plot to break integer division
_THIS_CENTURY = 100*divmod(DateTime.now().year, 100)[0]

def _iso_add_century(year):
    """
    According to ISO 8601, a two-digit year in an all-numeric date
    expression refers to the current century.
    If year has exactly two digits, add the century. Otherwise, return
    it unchanged.
    """
    if 0 <= year < 100:
        result = year + _THIS_CENTURY
    else:
        result = year
    return result

def numericDate(s, formats='ymd mdy dmy'):
    """
    If the input string s is a valid numeric date
    expression according to one of the formats given, return
    a DateTime object with default time components.
    Date formats, separated by a single space character, are
    packed into a string.

    If only one date format is given, raise a ValueError if
    the string cannot be interpreted, and raise a DateTime
    RangeError if it can be interpreted but is not a valid date.

    If more than one date format is given, try each of them in order
    until a valid interpretation is found.  If the string does
    not represent a valid date, return None.  You can use one
    format twice (e.g. ['ymd', 'ymd']) to test only one format but
    suppress exceptions.
    """
    if s is None: return None
    dt = None
    formatlist = formats.split()
    exceptions_ok = (len(formatlist) == 1)
    _s = str(s).strip()
    len_s = len(_s)
    if (len_s in (6, 8)) and s.isdigit():
        # Accept yyyymmdd or yymmdd
        k0 = len_s - 4; k1 = k0 + 2; k2 = k1 + 2
        yy = _iso_add_century(int(_s[0:k0]))
        mm = int(_s[k0:k1])
        dd = int(_s[k1:k2])
        try:
            dt = DateTime.DateTime(yy, mm, dd)
        except DateTime.RangeError, why:
            dt = None
            if exceptions_ok:
                raise DateTime.RangeError, "'%s' invalid: %s" % (_s, why)
    else:
        # Try the given formats in order
        for format in formatlist:
            format_re = _formatdict[format.lower()]
            match = format_re.search(_s)
            if match is None:
                continue
            year = match.group('year')
            month = match.group('month')
            day = match.group('day')
            yy = _iso_add_century(int(year))
            mm = int(month)
            dd = int(day)
            try:
                dt = DateTime.DateTime(yy, mm, dd)
            except DateTime.RangeError, why:
                dt = None
                if exceptions_ok:
                    raise DateTime.RangeError, "'%s' invalid: %s" % (_s, why)
            if dt is not None:
                break
        if dt is None and exceptions_ok:
            raise ValueError, "unrecognized date format: '%s'" % _s
    return dt

def numericTime(s):
    """
    If the input string s is a valid time expression of the
    form hh:mm:ss.sss or hh:mm:ss or hh:mm, return
    a corresponding DateTimeDelta object. Otherwise, return None.
    """
    if s is None: return None
    dt = None
    match = _timeRE.search(s)
    if match is not None:
        hour = match.group('hour')
        minute = match.group('minute')
        second = match.group('second')
        hh = int(hour); mm = int(minute)
        if second:
            ss = float(second)
        else:
            ss = 0.0
        try:
            dt = DateTime.DateTimeDelta(0, hh, mm, ss)
        except DateTime.RangeError:
            dt = None
    return dt

def numericDateTime(s, formats='ymd mdy dmy'):
    # Return a DateTime object or None, incorporating time data
    # if included in the string. If only one format is given,
    # and if the string is not a valid date-time expression
    # according to that format, raise an exception.
    if s is None: return None
    # ISO date-time may have T separating date and time
    _s = str(s).strip().replace('T', ' ')
    date_time = _s.split()
    d = numericDate(date_time[0], formats)
    if d is not None and len(date_time) > 1:
        t = numericTime(date_time[1])
        if t is not None:
            d = d + t
    return d

def _test_it(testcase, formats, timeonly=0):
    result = None
    if timeonly:
        try:
            dtd0 = numericTime(testcase[0])
            if dtd0 != testcase[1]:
                result = "Error: '%s' --> %s" % (testcase[0], repr(dtd0))
        except Exception, e:
            result = "Error: '%s' -- %s" % (testcase[0], str(e))
    else:
        try:
            dt0 = numericDateTime(testcase[0], formats)
            if dt0 != testcase[1]:
                result = "Error: '%s' --> %s" % (testcase[0], repr(dt0))
        except Exception, e:
            result = "Error: '%s' -- %s" % (testcase[0], str(e))
    return result

def test(formats='ymd mdy dmy'):
    from time import clock
    testcases = [ \
        # Time expressions
        ("12:13:14.56", DateTime.DateTimeDelta(0, 12, 13, 14.56)),
        ("12:13:14", DateTime.DateTimeDelta(0, 12, 13, 14)),
        ("12:13", DateTime.DateTimeDelta(0, 12, 13, 0)),
        # Date or date-time expressions (mostly)
        ("Ceci n'est pas une date", None),
        ("010803", DateTime.DateTime(2001, 8, 3)),
        ("20010803", DateTime.DateTime(2001, 8, 3)),
        ("20010803 12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        ("20010803T12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        ("01-08-03", DateTime.DateTime(2001, 8, 3)),
        ("2001-08-03", DateTime.DateTime(2001, 8, 3)),
        ("2001-8-3", DateTime.DateTime(2001, 8, 3)),
        ("2001-08-03 12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        ("2001-08-03T12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        # These should be correctly recognized if tested as mdy.
        ("08/03/2001", DateTime.DateTime(2001, 8, 3)),
        ("8/3/2001", DateTime.DateTime(2001, 8, 3)),
        ("08/03/2001 12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        ("08/03/2001T12:13:14.56", DateTime.DateTime(2001, 8, 3, 12, 13, 14.56)),
        # These can only be mdy
        ("08/23/2001", DateTime.DateTime(2001, 8, 23)),
        ("8/23/2001", DateTime.DateTime(2001, 8, 23)),
        ("08/23/2001 12:13:14.56", DateTime.DateTime(2001, 8, 23, 12, 13, 14.56)),
        # These can only be dmy
        ("23.08.2001", DateTime.DateTime(2001, 8, 23)),
        ("23.8.2001", DateTime.DateTime(2001, 8, 23)),
        ("23.08.2001 12:13:14.56", DateTime.DateTime(2001, 8, 23, 12, 13, 14.56)),
        ]
    print "\nTesting numdate.py with format(s) %s" % ", ".join(formats.split())
    t0 = clock()
    cases = 0
    for i in range(100):
        for testcase in testcases[0:3]:
            result = _test_it(testcase, formats, timeonly=1)
            cases = cases + 1
            if result and i == 0:
                print result

        for testcase in testcases[3:]:
            result = _test_it(testcase, formats, timeonly=0)
            cases = cases + 1
            if result and i == 0:
                print result
    t1 = clock()
    print "Done - %d cases tested in %1.5f sec." %  (cases, t1 - t0)

if __name__ == '__main__':
    test()
