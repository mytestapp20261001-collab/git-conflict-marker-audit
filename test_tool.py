import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def write(self,text):
        p=self.root/'file.txt';p.write_text(text);return p
    def test_ordinary_symbols_not_conflicts(self):
        p=self.write('=======\n<<<<<<<<<\nx >= y\n');self.assertEqual(tool.audit(p)['status'],'pass');self.assertEqual(self.call(p)[0],0)
    def test_complete_and_diff3(self):
        p=self.write('<<<<<<< ours\na\n||||||| base\nb\n=======\nc\n>>>>>>> theirs\n');r=tool.audit(p);self.assertEqual(r['summary']['complete_blocks'],1);self.assertEqual(self.codes(r),{'conflict_block'});self.assertEqual(self.call(p)[0],1);self.assertNotIn('ours',json.dumps(r))
    def test_unterminated_and_orphan(self):
        p=self.write('>>>>>>> end\n<<<<<<< start\nx\n');self.assertEqual(self.codes(tool.audit(p)),{'orphan_marker','unterminated_conflict'})
    def test_malformed_state_transitions(self):
        p=self.write('<<<<<<< a\n>>>>>>> b\n<<<<<<< c\n=======\n=======\n||||||| base\n>>>>>>> d\n');self.assertTrue({'end_before_separator','duplicate_separator','unexpected_base_marker','conflict_block'}<=self.codes(tool.audit(p)))
    def test_nested_and_custom_size(self):
        p=self.write('<<<<<<< a\n<<<<<<< b\n=======\n>>>>>>> c\n=======\n>>>>>>> d\n');self.assertIn('nested_conflict_start',self.codes(tool.audit(p)))
        p=self.write('<<<<<<<<< a\n=========\n>>>>>>>>> b\n');self.assertEqual(tool.audit(p,marker_size=9)['summary']['complete_blocks'],1)
    def test_unlabeled_opt_in(self):
        p=self.write('<<<<<<<\na\n=======\nb\n>>>>>>>\n');self.assertEqual(tool.audit(p)['status'],'pass');self.assertIn('conflict_block',self.codes(tool.audit(p,allow_unlabeled=True)))
    def test_limits_symlink_and_permissions(self):
        p=self.write('x\ny\n');self.assertEqual(tool.audit(p,max_lines=1)['status'],'error');self.assertEqual(tool.audit(p,max_bytes=1)['status'],'error');self.assertEqual(tool.audit(p,marker_size=2)['status'],'error')
        q=self.root/'link';q.symlink_to(p);self.assertEqual(tool.audit(q)['status'],'error')
        with mock.patch.object(tool,'read_file',side_effect=PermissionError):self.assertEqual(tool.audit(p)['status'],'error')
    def test_invalid_encoding_and_size_mismatch(self):
        p=self.write('<<<<<<< a\n=========\n');self.assertIn('marker_size_mismatch',self.codes(tool.audit(p)))
        p.write_bytes(b'\xff');self.assertEqual(tool.audit(p)['status'],'error')

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()


    def test_line_count_has_no_phantom_final_line(self):
        for text,count in [('',0),('normal',1),('normal\n',1),('normal\r\n',1),('\n',1),('a\n\n',2),('a\nb',2)]:
            with self.subTest(text=text):
                p=self.write(text);r=tool.audit(p,max_lines=max(1,count))
                self.assertEqual(r['status'],'pass');self.assertEqual(r['summary']['lines_scanned'],count)
                self.assertEqual(self.call(p,'--max-lines',str(max(1,count)))[0],0)
        p=self.write('a\nb\n');self.assertEqual(tool.audit(p,max_lines=1)['status'],'error')

    def test_only_lf_separates_lines(self):
        p=self.write('a\u2028b\u0085c\vd\r')
        r=tool.audit(p,max_lines=1);self.assertEqual(r['status'],'pass');self.assertEqual(r['summary']['lines_scanned'],1)
        p=self.write('<<<<<<< ours\n=======\n>>>>>>> theirs\n')
        r=tool.audit(p,max_lines=3);self.assertEqual(r['summary']['complete_blocks'],1)
        self.assertEqual(r['findings'][0]['end_line'],3)

if __name__=="__main__":unittest.main()
