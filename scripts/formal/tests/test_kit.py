import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import formal_kit as fk  # noqa: E402
import check_claims as cc  # noqa: E402
import check_mutants as cm  # noqa: E402

FIX = HERE / "fixtures"

GO_SRC = '''package p

import "fmt"

const raw = `func Fake() {
}`

// Comment with } and { braces
func Plain(a int) string {
	s := "}{ not braces"
	r := '}'
	q := '\\''
	b := `{{{`
	/* block } */
	f := func() int { return 1 }
	return fmt.Sprint(s, r, q, b, f(), a)
}

func (t *Tree[K]) Insert(k K) {
	if k == nil {
		return
	}
}

func (t Tree[K]) Get(k K) interface{} { return nil }

func Insert(x interface{}) struct{ A int } {
	return struct{ A int }{1}
}

func Gen[T interface{ ~int }](x T) T { return x }

func (c *Conn) Close() error { return nil }
func (c Other) Close() error { return nil }
'''

RS_SRC = r'''
use std::fmt;

pub struct Foo<'a> { s: &'a str }

impl<'a> Foo<'a> {
    pub fn new(s: &'a str) -> Foo<'a> {
        let c = '{';
        let d = '\'';
        let e = '\u{1F600}';
        let raw = r#"}}} "{" "#;
        let raw2 = r"{";
        let by = b'}';
        // } stray
        /* nested /* } */ } */
        let f = |x: i32| { x + 1 };
        let _ = (c, d, e, raw, raw2, by, f(1));
        Foo { s }
    }

    pub(crate) async fn run(&self) -> &'a str {
        fn inner() -> u8 { 1 }
        let _ = inner();
        self.s
    }
}

impl fmt::Display for Foo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.s)
    }
}

impl Other {
    fn fmt(&self) {}
}

pub trait Shape {
    fn area(&self) -> f64;
    fn double(&self) -> f64 { self.area() * 2.0 }
}

pub unsafe extern "C" fn ffi(x: *const u8) -> u8 { *x }

pub fn generic<T: Fn() -> u8>(f: T) -> [u8; 2] where T: Copy { [f(), 1] }

mod m {
    pub fn helper() -> u8 { 2 }
}

fn label<'a>(x: &'a str) -> &'a str {
    'outer: loop { break 'outer; }
    x
}
'''


def src_of(path, text, sym):
    return fk.symbol_source(path, text, sym)


class BraceMatcher(unittest.TestCase):
    def test_go_plain_covers_whole_function(self):
        s = src_of("a.go", GO_SRC, "Plain")
        self.assertTrue(s.startswith("func Plain"))
        self.assertTrue(s.rstrip().endswith("}"))
        self.assertIn("return fmt.Sprint", s)
        self.assertNotIn("Insert", s)

    def test_go_raw_string_at_top_is_not_a_func(self):
        names = [d.label for d in fk.find_go_decls(GO_SRC)]
        self.assertNotIn("Fake", names)

    def test_go_interface_and_struct_returns(self):
        with self.assertRaises(fk.KitError):
            src_of("a.go", GO_SRC, "Insert")
        s = src_of("a.go", GO_SRC, "func Insert")
        self.assertTrue(s.startswith("func Insert"))
        self.assertIn("struct{ A int }{1}", s)

    def test_go_generic_constraint_braces(self):
        s = src_of("a.go", GO_SRC, "Gen")
        self.assertEqual(s, "func Gen[T interface{ ~int }](x T) T { return x }")

    def test_go_ambiguity_requires_qualifier(self):
        with self.assertRaises(fk.KitError):
            src_of("a.go", GO_SRC, "Close")
        self.assertIn("Conn", src_of("a.go", GO_SRC, "(*Conn).Close"))
        self.assertIn("Other", src_of("a.go", GO_SRC, "Other.Close"))
        # pointer receiver also reachable as T.Name when unambiguous
        self.assertIn("Tree[K]) Insert", src_of("a.go", GO_SRC, "Tree.Insert"))

    def test_go_free_func_vs_method_same_name_is_ambiguous(self):
        with self.assertRaises(fk.KitError):
            src_of("a.go", GO_SRC + "\nfunc (z Z) Plain() {}\n", "Plain")

    def test_rust_new_with_tricky_literals(self):
        s = src_of("a.rs", RS_SRC, "Foo::new")
        self.assertTrue(s.strip().startswith("pub fn new"))
        self.assertIn("Foo { s }", s)
        self.assertNotIn("pub(crate) async fn run", s)

    def test_rust_lifetimes_do_not_swallow_code(self):
        s = src_of("a.rs", RS_SRC, "label")
        self.assertIn("'outer: loop", s)
        self.assertTrue(s.rstrip().endswith("}"))
        self.assertIn("    x\n}", s)

    def test_rust_prefixes_and_nested_fn(self):
        s = src_of("a.rs", RS_SRC, "Foo::run")
        self.assertIn("fn inner()", s)
        self.assertIn("self.s", s)
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_SRC, "inner")  # nested fns are not addressable
        self.assertIn("extern \"C\" fn ffi", src_of("a.rs", RS_SRC, "ffi"))

    def test_rust_where_and_arrow_in_generics(self):
        s = src_of("a.rs", RS_SRC, "generic")
        self.assertIn("[f(), 1]", s)

    def test_rust_trait_default_and_decl_only(self):
        d = src_of("a.rs", RS_SRC, "Shape::double")
        self.assertIn("self.area() * 2.0", d)
        a = src_of("a.rs", RS_SRC, "Shape::area")
        self.assertTrue(a.strip().endswith(";"))

    def test_rust_trait_impl_ambiguity(self):
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_SRC, "fmt")  # Display::fmt and Other::fmt
        self.assertIn("write!", src_of("a.rs", RS_SRC, "Foo::fmt"))
        self.assertIn("write!", src_of("a.rs", RS_SRC, "Display for Foo::fmt"))
        self.assertIn("fn fmt(&self) {}", src_of("a.rs", RS_SRC, "Other::fmt"))

    def test_rust_inline_mod(self):
        self.assertIn("fn helper", src_of("a.rs", RS_SRC, "m::helper"))
        self.assertIn("fn helper", src_of("a.rs", RS_SRC, "helper"))

    def test_missing_symbol(self):
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_SRC, "nope")

    def test_star_hashes_whole_file(self):
        self.assertEqual(src_of("a.rs", RS_SRC, "*"), RS_SRC)
        self.assertEqual(fk.hash_text("a  \nb\t\n"), fk.hash_text("a\nb\n"))

    def test_unterminated_constructs_fail_loudly(self):
        for bad, lang in (('let s = "abc', "rust"), ("/* open", "go"), ("x := `abc", "go"),
                          ('let r = r#"abc"', "rust")):
            with self.assertRaises(fk.KitError):
                fk.mask_source(bad, lang)

    def test_whitespace_normalization_only_trailing(self):
        a = "fn f() {\n    1   \n}\n"
        b = "fn f() {\n    1\n}\n"
        c = "fn f() {\n  1\n}\n"
        self.assertEqual(fk.hash_text(a), fk.hash_text(b))
        self.assertNotEqual(fk.hash_text(a), fk.hash_text(c))

    def test_rust_const_generic_braces_in_signature(self):
        # the `{ N }` inside the generics must not be taken as the body
        src = "fn f() -> Foo<{ N }> {\n    let k = 1;\n    k\n}\nfn g() {}\n"
        s = src_of("a.rs", src, "f")
        self.assertTrue(s.endswith("    k\n}"), s)
        src = "impl Foo<{ N }> {\n    fn m(&self) -> u8 { 1 }\n}\n"
        self.assertIn("{ 1 }", src_of("a.rs", src, "Foo::m"))

    def test_match_brace_on_masked(self):
        t = fk.mask_source("{ '}' \"}\" // }\n }", "go")
        self.assertEqual(fk.match_brace(t, 0), len(t) - 1)


RS_QUAL = '''
pub trait CtEq {
    fn ct_eq(&self, o: &Self) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, o: &Self) -> bool {
        self == o
    }
}
pub struct Secret;
impl From<u8> for Secret {
    fn from(x: u8) -> Self {
        Secret
    }
}
impl From<String> for Secret {
    fn from(x: String) -> Self {
        Secret
    }
}
pub struct FileStorage;
impl FileStorage {
    pub fn reload(&self) {
        one();
    }
}
impl StorageBackend for FileStorage {
    fn reload(&self) {
        two();
    }
}
impl<T: Clone> Wrap<T> {
    fn get(&self) -> u8 {
        7
    }
}
pub fn validate_typed() {
    three();
}
mod tests {
    fn validate_typed() {
        four();
    }
}
#[cfg(unix)]
fn twin() {
    five();
}
#[cfg(not(unix))]
fn twin() {
    six();
}
'''


class RustQualifiers(unittest.TestCase):
    def test_non_path_self_type(self):
        s = src_of("a.rs", RS_QUAL, "CtEq for [u8]::ct_eq")
        self.assertIn("self == o", s)
        t = src_of("a.rs", RS_QUAL, "CtEq::ct_eq")
        self.assertTrue(t.strip().endswith(";"), "Trait::name names the trait's own item")

    def test_trait_generic_args(self):
        self.assertIn("u8", src_of("a.rs", RS_QUAL, "From<u8> for Secret::from").split("{")[0])
        self.assertIn("String", src_of("a.rs", RS_QUAL, "From<String> for Secret::from").split("{")[0])
        self.assertIn("String", src_of("a.rs", RS_QUAL, "From< String >  for Secret::from").split("{")[0])
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_QUAL, "Secret::from")

    def test_inherent_impl_method(self):
        self.assertIn("one()", src_of("a.rs", RS_QUAL, "impl FileStorage::reload"))
        self.assertIn("two()", src_of("a.rs", RS_QUAL, "StorageBackend for FileStorage::reload"))
        self.assertIn("7", src_of("a.rs", RS_QUAL, "impl Wrap<T>::get"))
        self.assertIn("7", src_of("a.rs", RS_QUAL, "impl Wrap::get"))

    def test_crate_level_free_fn(self):
        self.assertIn("three()", src_of("a.rs", RS_QUAL, "crate::validate_typed"))
        self.assertIn("four()", src_of("a.rs", RS_QUAL, "tests::validate_typed"))
        self.assertIn("four()", src_of("a.rs", RS_QUAL, "crate::tests::validate_typed"))
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_QUAL, "validate_typed")
        with self.assertRaises(fk.KitError):
            src_of("a.rs", RS_QUAL, "fn validate_typed")

    def test_true_duplicates_say_so(self):
        with self.assertRaises(fk.KitError) as cm:
            src_of("a.rs", RS_QUAL, "twin")
        msg = str(cm.exception)
        self.assertIn("no qualifier separates", msg)
        self.assertIn('"*"', msg)
        self.assertIn("line 46", msg)
        self.assertIn("line 50", msg)

    def test_ambiguity_message_lists_distinct_candidates(self):
        with self.assertRaises(fk.KitError) as cm:
            src_of("a.rs", RS_QUAL, "Secret::from")
        msg = str(cm.exception)
        self.assertIn("From<u8> for Secret::from", msg)
        self.assertIn("From<String> for Secret::from", msg)


class YamlReader(unittest.TestCase):
    def test_real_workflows_ci_required_equality(self):
        for repo in ("averin", "vultrino", "govder", "leria", "feir-os"):
            text = (FIX / ("ci-%s.yml" % repo)).read_text()
            jobs = fk.parse_workflow_jobs(text, repo)
            gate = jobs["ci-required"]
            unconditional = {j for j, v in jobs.items() if j != "ci-required" and not v.has_if}
            # feir-os deliberately keeps its path-filtered frontend-browser job in needs
            allowed = {"frontend-browser"} if repo == "feir-os" else set()
            self.assertEqual(set(gate.needs), unconditional | allowed, repo)
            self.assertTrue(gate.has_if)

    def test_known_conditional_jobs(self):
        j = fk.parse_workflow_jobs((FIX / "ci-averin.yml").read_text(), "averin")
        for name in ("formal-mutants-full", "formal-kani-strings-ascii", "formal-kani-strings-pure"):
            self.assertTrue(j[name].has_if, name)
        self.assertFalse(j["core"].has_if)
        g = fk.parse_workflow_jobs((FIX / "ci-govder.yml").read_text(), "govder")
        self.assertTrue(g["e2e-four-plane"].has_if)  # if: >-

    def test_compact_needs_block_list_error_is_explicit(self):
        y = "name: x\njobs:\n  a:\n    runs-on: x\n  b:\n    needs:\n    - a\n    runs-on: x\n"
        with self.assertRaises(fk.YamlError) as cm:
            fk.parse_workflow_jobs(y, "t")
        self.assertIn("indented deeper", str(cm.exception))

    def test_compact_sequence_under_a_job_key(self):
        # GitHub starter-workflow style: `- uses:` at the same indent as `steps:`.
        y = ("jobs:\n  a:\n    runs-on: x\n    steps:\n    - uses: actions/checkout@v4\n"
             "    - if: false\n      run: |\n        echo hi\n    if: always()\n  b:\n    needs: [a]\n"
             "    steps:\n    - run: echo\n")
        j = fk.parse_workflow_jobs(y, "t")
        self.assertTrue(j["a"].has_if)
        self.assertIsNone(j["a"].needs)
        self.assertFalse(j["b"].has_if)
        self.assertEqual(j["b"].needs, ["a"])
        # a dash line after a key that has a value is still an error
        bad = "jobs:\n  a:\n    runs-on: x\n    - uses: y\n"
        with self.assertRaises(fk.YamlError):
            fk.parse_workflow_jobs(bad, "t")

    def test_needs_forms(self):
        y = ("name: x\njobs:\n  a:\n    runs-on: x\n  b:\n    needs: a\n    runs-on: x\n"
             "  c:\n    needs: [a,\n      b]\n    runs-on: x\n  d:\n    needs:\n      - a  # c\n      - 'b'\n    runs-on: x\n")
        j = fk.parse_workflow_jobs(y)
        self.assertEqual(j["b"].needs, ["a"])
        self.assertEqual(j["c"].needs, ["a", "b"])
        self.assertEqual(j["d"].needs, ["a", "b"])
        self.assertIsNone(j["a"].needs)

    def test_block_scalar_content_is_not_structure(self):
        y = ("jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: |\n          if: sneaky\n"
             "          needs: [zzz]\n        shell: bash\n")
        j = fk.parse_workflow_jobs(y)
        self.assertFalse(j["a"].has_if)
        self.assertIsNone(j["a"].needs)

    def test_comment_and_quote_handling(self):
        y = "jobs:\n  a:\n    runs-on: x # if: no\n    # if: no\n    steps:\n      - run: echo '#' \"if:\"\n"
        self.assertFalse(fk.parse_workflow_jobs(y)["a"].has_if)

    def test_fails_loudly(self):
        bad = {
            "no jobs": "name: x\n",
            "tab": "jobs:\n\ta:\n\t\truns-on: x\n",
            "flow jobs": "jobs: {a: {runs-on: x}}\n",
            "anchor": "jobs:\n  a: &x\n    runs-on: x\n",
            "alias job": "jobs:\n  a:\n    <<: *x\n    runs-on: x\n",
            "dup job": "jobs:\n  a:\n    runs-on: x\n  a:\n    runs-on: x\n",
            "dup if": "jobs:\n  a:\n    if: true\n    if: false\n    runs-on: x\n",
            "expr needs": "jobs:\n  a:\n    needs: ${{ fromJSON(x) }}\n    runs-on: x\n",
            "empty needs": "jobs:\n  a:\n    needs:\n    runs-on: x\n",
            "two docs": "jobs:\n  a:\n    runs-on: x\n---\njobs:\n",
            "bad indent": "jobs:\n  a:\n    runs-on: x\n   b:\n    runs-on: x\n",
            "unterminated list": "jobs:\n  a:\n    needs: [x\n    runs-on: x\n",
            "empty job": "jobs:\n  a:\n  b:\n    runs-on: x\n",
        }
        for name, y in bad.items():
            with self.assertRaises(fk.YamlError, msg=name):
                fk.parse_workflow_jobs(y, name)


_TEMP_DIRS = []


def tearDownModule():
    for d in _TEMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


def make_repo(files, mutants=None):
    d = Path(tempfile.mkdtemp(prefix="kit-test-"))
    _TEMP_DIRS.append(d)
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")

    def git(*a):
        return subprocess.run(["git", *a], cwd=str(d), env=env, check=True, capture_output=True, text=True)
    git("init", "-q", "-b", "main")
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    return d, git


CI_OK = ("name: ci\non: push\njobs:\n  go:\n    runs-on: x\n  nightly:\n    if: github.event_name == 'schedule'\n"
         "    runs-on: x\n  ci-required:\n    if: always()\n    needs: [go]\n    runs-on: x\n")

GO_FILE = "package p\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc Other() {}\n"


def base_claims(**over):
    c = {
        "schema": 1,
        "overclaim_denylist": {"phrases": ["fully verified"], "globs": ["docs/**/*.md"]},
        "claims": [{
            "id": "add-sum", "statement": "Add returns the sum.", "method": "test",
            "artifacts": ["p.go"], "gates": ["go"], "detector": "grep -q 'a + b' p.go",
            "covers": [{"path": "p.go", "symbol": "Add", "sha256": ""}],
            "mutants": ["add-sub"], "does_not_establish": "Overflow behaviour.",
        }],
    }
    c.update(over)
    return c


class ClaimsChecks(unittest.TestCase):
    def setUp(self):
        self.d, self.git = make_repo({
            "p.go": GO_FILE, ".github/workflows/ci.yml": CI_OK, "docs/a.md": "plain text\n",
            "formal/mutants/add-sub.patch": "",
        })
        self.claims = self.d / "formal" / "claims.json"
        self.claims.write_text(json.dumps(base_claims(), indent=2) + "\n")

    def run_cc(self, **kw):
        return cc.run_all(self.d, self.claims, **kw)

    def failures(self, rep):
        return [(c, m) for c, ok, m in rep.rows if not ok]

    def test_empty_hash_fails_then_relock_passes_and_is_stable(self):
        rep, _ = self.run_cc()
        self.assertTrue(any(c.startswith("covers") for c, _ in self.failures(rep)))
        rep, changes = self.run_cc(do_relock=True)
        self.assertEqual(len(changes), 1)
        self.assertIn("relocked p.go Add", changes[0])
        self.assertEqual(self.failures(rep), [])
        rep, changes = self.run_cc()
        self.assertEqual(self.failures(rep), [])
        self.assertEqual(changes, [])
        # file layout preserved (indent 2, trailing newline)
        self.assertIn('\n      "claims"'[:3], self.claims.read_text())

    def test_drift_detected_and_relock_restricted(self):
        self.run_cc(do_relock=True)
        (self.d / "p.go").write_text(GO_FILE.replace("a + b", "a - b"))
        rep, _ = self.run_cc()
        self.assertTrue(any("source changed" in m for _, m in self.failures(rep)))
        # unrelated symbol edit does not disturb the lock
        (self.d / "p.go").write_text(GO_FILE.replace("func Other() {}", "func Other() { _ = 1 }"))
        rep, _ = self.run_cc()
        self.assertEqual(self.failures(rep), [])
        # restricted relock that does not match leaves drift in place
        (self.d / "p.go").write_text(GO_FILE.replace("a + b", "a * b"))
        rep, changes = self.run_cc(do_relock=True, only=["other.go"])
        self.assertEqual(changes, [])
        self.assertTrue(self.failures(rep))
        rep, changes = self.run_cc(do_relock=True, only=["p.go:Add"])
        self.assertEqual(len(changes), 1)
        self.assertEqual(self.failures(rep), [])

    def test_missing_symbol_cannot_be_relocked(self):
        d = json.loads(self.claims.read_text())
        d["claims"][0]["covers"][0]["symbol"] = "Gone"
        self.claims.write_text(json.dumps(d))
        rep, changes = self.run_cc(do_relock=True)
        self.assertEqual(changes, [])
        self.assertTrue(any("not found" in m for _, m in self.failures(rep)))

    def test_schema_errors(self):
        for mutate, frag in (
            (lambda d: d["claims"].append(dict(d["claims"][0])), "duplicate"),
            (lambda d: d["claims"][0].update(method="vibes"), "method"),
            (lambda d: d["claims"][0].update(does_not_establish=""), "does_not_establish"),
            (lambda d: d["claims"][0].update(covers=[]), "covers"),
            (lambda d: d["claims"][0].update(typo=1), "unknown key"),
            (lambda d: d.update(schema=2), "schema"),
            (lambda d: d["claims"][0].update(artifacts=["../x"]), "inside the repo"),
        ):
            d = base_claims()
            mutate(d)
            self.claims.write_text(json.dumps(d))
            rep, _ = self.run_cc()
            self.assertTrue(any(frag in m for _, m in self.failures(rep)), frag)

    def test_artifact_gate_mutant_checks(self):
        d = base_claims()
        d["claims"][0]["artifacts"] = ["missing.txt"]
        d["claims"][0]["gates"] = ["no-such-job"]
        d["claims"][0]["mutants"] = ["ghost"]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        msgs = " | ".join(c + " " + m for c, m in self.failures(rep))
        self.assertIn("path does not exist", msgs)
        self.assertIn("no job with this id", msgs)
        self.assertIn("ghost.patch is missing", msgs)

    def test_denylist(self):
        self.run_cc(do_relock=True)
        (self.d / "docs" / "a.md").write_text("This is Fully Verified code\n")
        rep, _ = self.run_cc()
        self.assertTrue(any("docs/a.md:1" in m for _, m in self.failures(rep)))
        # a phrase wrapped across lines (hard-wrapped docs) is still found
        (self.d / "docs" / "a.md").write_text("line one\nthe code is fully\n  verified here\n")
        rep, _ = self.run_cc()
        self.assertTrue(any("docs/a.md:2" in m for _, m in self.failures(rep)), self.failures(rep))
        # a file that is not valid UTF-8 is still scanned, with a warning
        (self.d / "docs" / "a.md").write_bytes(b"caf\xe9 code is fully verified\n")
        rep, _ = self.run_cc()
        self.assertTrue(any("docs/a.md:1" in m for _, m in self.failures(rep)), rep.render())
        self.assertTrue(any("not valid UTF-8" in m for _, _, m in rep.rows), rep.render())
        (self.d / "docs" / "a.md").write_text("ok\n")
        d = json.loads(self.claims.read_text())
        d["overclaim_denylist"]["globs"] = ["nope/**/*.md"]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        self.assertTrue(any("matched no files" in m for _, m in self.failures(rep)))

    def ci_with(self, extra_jobs, needs):
        y = ("name: ci\non: push\njobs:\n  go:\n    runs-on: x\n" + extra_jobs +
             "  ci-required:\n    if: always()\n    needs: [%s]\n    runs-on: x\n" % needs)
        (self.d / ".github/workflows/ci.yml").write_text(y)

    def test_ci_required_missing_and_extra(self):
        self.run_cc(do_relock=True)
        self.ci_with("  lint:\n    runs-on: x\n", "go")
        rep, _ = self.run_cc()
        self.assertTrue(any("missing from needs: lint" in m for _, m in self.failures(rep)))
        self.ci_with("  nightly:\n    if: false\n    runs-on: x\n", "go, nightly")
        rep, _ = self.run_cc()
        self.assertTrue(any("not unconditional jobs" in m and "nightly" in m for _, m in self.failures(rep)))

    def test_ci_required_exempt(self):
        self.run_cc(do_relock=True)
        self.ci_with("  lint:\n    runs-on: x\n", "go")
        d = json.loads(self.claims.read_text())
        d["ci_required_exempt"] = [{"job": "lint", "reason": "advisory only"}]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        self.assertEqual(self.failures(rep), [])
        d["ci_required_exempt"] = [{"job": "lint", "reason": ""}]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        self.assertTrue(self.failures(rep))

    def test_ci_required_conditional_allowance_real_feir_os(self):
        (self.d / ".github/workflows/ci.yml").write_text((FIX / "ci-feir-os.yml").read_text())
        d = json.loads(self.claims.read_text())
        # the real file needs a gate job named in the claim; point the claim at a job that exists
        d["claims"][0]["gates"] = ["go"]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        self.assertTrue(any("not unconditional jobs" in m and "frontend-browser" in m
                            for c, m in self.failures(rep) if c == "ci-required"))
        d["ci_required_conditional"] = [{"job": "frontend-browser", "reason": "path filtered, gate tolerates a skip"}]
        self.claims.write_text(json.dumps(d))
        rep, _ = self.run_cc()
        self.assertEqual([f for f in self.failures(rep) if f[0] == "ci-required"], [])

    def test_ci_required_conditional_validation(self):
        self.run_cc(do_relock=True)
        def fails(entries, ci=None):
            if ci:
                self.ci_with(*ci)
            d = json.loads(self.claims.read_text())
            d["ci_required_conditional"] = entries
            self.claims.write_text(json.dumps(d))
            rep, _ = self.run_cc()
            return [m for c, m in self.failures(rep) if c in ("ci-required", "schema")]
        cond = "  slow:\n    if: github.event_name == 'push'\n    runs-on: x\n"
        ok = fails([{"job": "slow", "reason": "ok"}], (cond, "go, slow"))
        self.assertEqual(ok, [])
        self.assertTrue(any("does not exist" in m for m in fails([{"job": "nope", "reason": "x"}])))
        self.assertTrue(fails([{"job": "slow", "reason": " "}]))
        # job has an if but is not in needs
        self.assertTrue(any("not in ci-required needs" in m
                            for m in fails([{"job": "slow", "reason": "x"}], (cond, "go"))))
        # job has no if
        self.assertTrue(any("has no job-level if" in m for m in fails(
            [{"job": "lint", "reason": "x"}], ("  lint:\n    runs-on: x\n", "go, lint"))))
        # any other conditional job in needs still fails
        self.assertTrue(any("not unconditional" in m for m in fails([], (cond, "go, slow"))))

    def test_unparsable_workflow_fails_loudly(self):
        (self.d / ".github/workflows/other.yml").write_text("jobs: {a: 1}\n")
        rep, _ = self.run_cc()
        self.assertTrue(any(c.startswith("workflow parse") for c, _ in self.failures(rep)))


class MutantRunner(unittest.TestCase):
    def build(self, detector_ok="grep -q ok target.txt", extra=None):
        files = {"target.txt": "ok\n", "other.txt": "x\n"}
        d, git = make_repo(files)
        patches = {}

        def mk(name, fn):
            fn()
            patch = subprocess.run(["git", "diff"], cwd=str(d), capture_output=True, text=True, check=True).stdout
            git("checkout", "--", ".")
            patches[name] = patch
        mk("kills", lambda: (d / "target.txt").write_text("bad\n"))
        mk("survives", lambda: (d / "other.txt").write_text("y\n"))
        mk("noapply", lambda: (d / "target.txt").write_text("bad\n"))
        patches["noapply"] = patches["noapply"].replace("-ok", "-zzz")
        mut_dir = d / "formal" / "mutants"
        mut_dir.mkdir(parents=True)
        for k, v in patches.items():
            (mut_dir / (k + ".patch")).write_text(v)
        claims = {
            "schema": 1,
            "claims": [{
                "id": "c1", "statement": "s", "method": "test", "artifacts": [], "gates": ["go"],
                "detector": detector_ok, "covers": [{"path": "target.txt", "symbol": "*", "sha256": ""}],
                "mutants": ["kills", "survives", "noapply"], "does_not_establish": "n",
            }],
            "mutants": {"kills": {"tier": "fast"}, "survives": {"tier": "fast"}, "noapply": {"tier": "full"}},
        }
        if extra:
            extra(claims)
        (d / "formal" / "claims.json").write_text(json.dumps(claims))
        git("add", "-A")
        git("commit", "-q", "-m", "mutants")
        return d

    def go(self, d, **kw):
        import io
        buf = io.StringIO()
        code = cm.run(d, d / "formal" / "claims.json", out=buf, timeout=30, **kw)
        return code, buf.getvalue()

    def worktrees(self, d):
        return subprocess.run(["git", "worktree", "list"], cwd=str(d), capture_output=True, text=True).stdout

    def test_killed_survived_and_noapply(self):
        d = self.build()
        code, out = self.go(d, tier="full")
        self.assertEqual(code, 1)
        self.assertIn("killed    kills", out)
        self.assertIn("SURVIVED  survives", out)
        self.assertIn("error     noapply", out)
        self.assertIn("1 killed, 1 survived, 1 error", out)
        self.assertEqual(len(self.worktrees(d).strip().splitlines()), 1)
        self.assertEqual((d / "target.txt").read_text(), "ok\n")

    def test_fast_tier_and_only(self):
        d = self.build()
        code, out = self.go(d, tier="fast")
        self.assertNotIn("noapply", out)
        self.assertEqual(code, 1)
        code, out = self.go(d, tier="full", only="kills")
        self.assertEqual(code, 0, out)
        self.assertIn("1 killed", out)

    def test_json_report_and_scratch_option(self):
        d = self.build()
        j = d.parent / ("report-%s.json" % d.name)
        scratch = d.parent / ("scratch-%s" % d.name)
        code, _ = self.go(d, tier="full", only="kills", json_path=j, scratch=scratch)
        self.assertEqual(code, 0)
        rep = json.loads(j.read_text())
        self.assertEqual(rep["results"][0]["status"], "killed")
        self.assertFalse(scratch.exists())
        j.unlink()

    def test_failing_baseline_blocks_run(self):
        d = self.build(detector_ok="grep -q nothere target.txt")
        code, out = self.go(d, tier="full")
        self.assertEqual(code, 1)
        self.assertIn("baseline failed", out)
        self.assertNotIn("killed    kills", out)
        self.assertEqual(len(self.worktrees(d).strip().splitlines()), 1)

    def test_timeout_is_not_a_kill(self):
        d = self.build(detector_ok="sleep 20")
        import io
        buf = io.StringIO()
        code = cm.run(d, d / "formal" / "claims.json", only="kills", out=buf, timeout=1)
        self.assertEqual(code, 1)
        self.assertIn("baseline", buf.getvalue())

    def test_empty_tier_selection_fails_unless_allowed(self):
        def all_full(c):
            c["mutants"] = {}
        d = self.build(extra=all_full)
        code, out = self.go(d, tier="fast")
        self.assertEqual(code, 1, out)
        self.assertIn("no mutants selected", out)
        code, out = self.go(d, tier="fast", allow_empty=True)
        self.assertEqual(code, 0, out)

    def test_kill_without_changing_a_covered_symbol_is_an_error(self):
        def cover_other(c):
            c["claims"][0]["covers"] = [{"path": "other.txt", "symbol": "*", "sha256": ""}]
        d = self.build(extra=cover_other)
        code, out = self.go(d, tier="full", only="kills")
        self.assertEqual(code, 1, out)
        self.assertIn("error     kills", out)
        self.assertIn("vacuous", out)
        self.assertNotIn("killed    kills", out)

    def test_detector_running_check_claims_warns(self):
        d = self.build(detector_ok="grep -q ok target.txt && echo python3 scripts/formal/check_claims.py >/dev/null")
        code, out = self.go(d, tier="full", only="kills")
        self.assertIn("WARNING", out)
        self.assertIn("check_claims.py", out)

    def test_unknown_only(self):
        d = self.build()
        code, out = self.go(d, only="nope")
        self.assertEqual(code, 2)

    def test_hidden_check_claims_cannot_kill_through_drift_lock(self):
        # The detector runs check_claims.py from a script, so the command text does
        # not mention it. An equivalent mutant (target still contains "ok") must
        # SURVIVE: the drift lock alone is not evidence that the gate bites.
        kit = HERE.parent
        files = {
            "target.txt": "ok\n",
            ".github/workflows/ci.yml": CI_OK,
            "gate.sh": "python3 scripts/formal/check_claims.py >/dev/null || exit 3\ngrep -qx ok target.txt\n",
        }
        for f in ("formal_kit.py", "check_claims.py"):
            files["scripts/formal/" + f] = (kit / f).read_text()
        d, git = make_repo(files)
        (d / "target.txt").write_text("ok\nequivalent\n")
        equiv = subprocess.run(["git", "diff"], cwd=str(d), capture_output=True, text=True, check=True).stdout
        (d / "target.txt").write_text("bad\n")
        real = subprocess.run(["git", "diff"], cwd=str(d), capture_output=True, text=True, check=True).stdout
        git("checkout", "--", ".")
        (d / "formal" / "mutants").mkdir(parents=True)
        (d / "formal" / "mutants" / "equiv.patch").write_text(equiv)
        (d / "formal" / "mutants" / "real.patch").write_text(real)
        claims = d / "formal" / "claims.json"
        claims.write_text(json.dumps({
            "schema": 1,
            "claims": [{
                "id": "c1", "statement": "s", "method": "test", "artifacts": [], "gates": ["go"],
                "detector": "sh gate.sh", "covers": [{"path": "target.txt", "symbol": "*", "sha256": ""}],
                "mutants": ["equiv", "real"], "does_not_establish": "n",
            }],
        }, indent=2) + "\n")
        rep, _ = cc.run_all(d, claims, do_relock=True)
        self.assertFalse(rep.failed, rep.render())
        git("add", "-A")
        git("commit", "-q", "-m", "claims")
        code, out = self.go(d, tier="full")
        self.assertIn("SURVIVED  equiv", out)
        # killed by the grep (exit 1), not by the claims checker (exit 3)
        self.assertIn("killed    real (claim c1, tier full) detector exit 1", out)
        self.assertEqual(code, 1, out)
        self.assertEqual(len(self.worktrees(d).strip().splitlines()), 1)

    def test_detector_output_that_is_not_utf8_does_not_crash(self):
        d = self.build(detector_ok="grep -q ok target.txt || { printf 'bad \\377\\376 bytes'; exit 1; }")
        code, out = self.go(d, tier="full", only="kills")
        self.assertEqual(code, 0, out)
        self.assertIn("killed    kills", out)

    def test_files_created_by_a_mutant_do_not_leak_into_the_next(self):
        # a-creates adds new.txt; its detector also edits target.txt, so `git apply -R`
        # fails and the tree is restored by checkout. new.txt must not survive into
        # b-probe, whose detector would otherwise fail (a false kill).
        def extra(c):
            c["claims"][0]["mutants"] = ["a-creates", "b-probe"]
            c["mutants"] = {
                "a-creates": {"detector": "if test -f new.txt; then echo x >> target.txt; exit 1; fi; grep -q ok target.txt"},
                "b-probe": {"detector": "test ! -f new.txt && grep -q ok target.txt"},
            }
        d = self.build(extra=extra)
        (d / "target.txt").write_text("ok\nmut\n")
        (d / "new.txt").write_text("created\n")
        subprocess.run(["git", "add", "-N", "new.txt"], cwd=str(d), check=True)
        creates = subprocess.run(["git", "diff"], cwd=str(d), capture_output=True, text=True, check=True).stdout
        subprocess.run(["git", "reset", "-q", "new.txt"], cwd=str(d), check=True)
        (d / "new.txt").unlink()
        (d / "target.txt").write_text("ok2\n")
        probe = subprocess.run(["git", "diff"], cwd=str(d), capture_output=True, text=True, check=True).stdout
        subprocess.run(["git", "checkout", "--", "."], cwd=str(d), check=True)
        (d / "formal" / "mutants" / "a-creates.patch").write_text(creates)
        (d / "formal" / "mutants" / "b-probe.patch").write_text(probe)
        for p in ("kills", "survives", "noapply"):
            (d / "formal" / "mutants" / (p + ".patch")).unlink()
        subprocess.run(["git", "add", "-A"], cwd=str(d), check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "m2"],
                       cwd=str(d), check=True)
        code, out = self.go(d, tier="full")
        self.assertIn("killed    a-creates", out)
        self.assertIn("SURVIVED  b-probe", out)


if __name__ == "__main__":
    unittest.main()
