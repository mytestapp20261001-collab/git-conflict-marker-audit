#!/usr/bin/env python3
"""Recognize scoped Git-style conflict blocks and malformed marker sequences."""
import re
from _support import InputError, Parser, Report, cli, guarded, limits, positive, read_file
TOOL='git-conflict-marker-audit'
MARKER=re.compile(r'^([<>=|])\1{2,}(?: (.+))?$')

def marker(line,size,allow_unlabeled):
    match=MARKER.fullmatch(line)
    if not match:return None
    char=match[1];run=len(line)-len(line.lstrip(char));label=match[2]
    if char=='=' and label is not None:return None
    if char!='=' and not (label and label.strip()) and not allow_unlabeled:return None
    return char,run

@guarded(TOOL)
def audit(path, *, marker_size=7,allow_unlabeled=False,max_bytes=16777216,max_lines=500000,max_open_blocks=128,max_findings=1000):
    limits(marker_size=marker_size,max_bytes=max_bytes,max_lines=max_lines,max_open_blocks=max_open_blocks,max_findings=max_findings)
    if not 3<=marker_size<=64:raise InputError('marker size must be between 3 and 64')
    data=read_file(path,max_bytes)
    try:text=data.decode('utf-8','strict')
    except UnicodeDecodeError:raise InputError('expected UTF-8 text') from None
    if '\x00' in text:raise InputError('NUL-containing input is outside the text audit scope')
    report=Report(TOOL,max_findings);stack=[];complete=0;lines=0
    # LF terminates a line; it does not create an extra empty line at EOF.
    # Do not use splitlines(): other Unicode separators are ordinary content.
    logical_lines=text.split('\n')
    if logical_lines[-1]=='':logical_lines.pop()
    for number,line in enumerate(logical_lines,1):
        lines=number
        if number>max_lines:raise InputError('line limit exceeded')
        if line.endswith('\r'):line=line[:-1]
        current=marker(line,marker_size,allow_unlabeled)
        if current is None:continue
        char,width=current
        if width!=marker_size:
            if stack:report.add('marker_size_mismatch',line=number,expected=marker_size,actual=width)
            continue
        if char=='<':
            if stack:report.add('nested_conflict_start',line=number)
            if len(stack)>=max_open_blocks:raise InputError('open conflict-block limit exceeded')
            stack.append({'start':number,'state':'ours'})
        elif not stack:
            if char in ('>','|'):report.add('orphan_marker',line=number,kind='end' if char=='>' else 'base')
            # A free-standing row of '=' characters is normal prose/code, not a conflict.
        elif char=='|':
            if stack[-1]['state']!='ours':report.add('unexpected_base_marker',line=number)
            else:stack[-1]['state']='base'
        elif char=='=':
            if stack[-1]['state']=='theirs':report.add('duplicate_separator',line=number)
            else:stack[-1]['state']='theirs'
        elif char=='>':
            block=stack.pop()
            if block['state']=='theirs':
                complete+=1;report.add('conflict_block',start_line=block['start'],end_line=number)
            else:report.add('end_before_separator',start_line=block['start'],end_line=number)
    for block in stack:report.add('unterminated_conflict',start_line=block['start'],state=block['state'])
    return report.finish({'lines_scanned':lines,'complete_blocks':complete,'open_blocks':len(stack),'marker_size':marker_size})

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument('file');p.add_argument('--allow-unlabeled',action='store_true')
    for name,default in [('marker-size',7),('max-bytes',16777216),('max-lines',500000),('max-open-blocks',128),('max-findings',1000)]:p.add_argument('--'+name,type=positive,default=default)
    a=vars(p.parse_args());path=a.pop('file');return audit(path,**a)
if __name__=='__main__':raise SystemExit(cli(TOOL,parse_and_audit))
