"""Tests for guardbunny.parser — structural parsing of .gb workflow files."""

import pytest
from guardbunny.parser import (
    ConditionStep,
    DoStep,
    ParseError,
    RepeatStep,
    WorkflowSpec,
    parse,
)


# ── Valid workflows ───────────────────────────────────────────────────────────


def test_parse_minimal_do_step():
    text = """
version: "1.0"
name: "minimal"
steps:
  - id: read_file
    do:
      action: file.read
      args:
        path: /workspace/hello.txt
    emit:
      content: "${steps.read_file.result.content}"
"""
    spec = parse(text)
    assert isinstance(spec, WorkflowSpec)
    assert spec.name == "minimal"
    assert spec.version == "1.0"
    assert len(spec.steps) == 1
    step = spec.steps[0]
    assert isinstance(step, DoStep)
    assert step.id == "read_file"
    assert step.action.type == "file.read"
    assert step.action.args["path"] == "/workspace/hello.txt"
    assert step.emit.mappings["content"] == "${steps.read_file.result.content}"


def test_parse_empty_steps():
    spec = parse('version: "1.0"\nname: "empty"\nsteps: []')
    assert spec.steps == ()


def test_parse_input_output_schemas():
    text = """
version: "1.0"
name: "schema_test"
input:
  file_path: {type: string}
output:
  content: {type: string}
steps: []
"""
    spec = parse(text)
    assert spec.input_schema == {"file_path": {"type": "string"}}
    assert spec.output_schema == {"content": {"type": "string"}}


def test_parse_condition_step():
    text = """
version: "1.0"
name: "cond"
steps:
  - id: branch
    condition:
      test: "input.flag == True"
      then:
        - id: on_true
          do:
            action: file.read
            args:
              path: /workspace/a.txt
          emit: {}
      else:
        - id: on_false
          do:
            action: file.write
            args:
              path: /workspace/b.txt
              content: "nope"
          emit: {}
"""
    spec = parse(text)
    step = spec.steps[0]
    assert isinstance(step, ConditionStep)
    assert step.id == "branch"
    assert step.test == "input.flag == True"
    assert len(step.then_steps) == 1
    assert len(step.else_steps) == 1
    assert isinstance(step.then_steps[0], DoStep)
    assert step.then_steps[0].id == "on_true"


def test_parse_repeat_step():
    text = """
version: "1.0"
name: "loop"
steps:
  - id: collect
    repeat:
      times: 3
      do:
        action: http.fetch
        args:
          url: "https://api.example.com/item/${vars.loop.index}"
          method: GET
    emit:
      items:
        merge: append
        value: "${steps.collect.result.body}"
"""
    spec = parse(text)
    step = spec.steps[0]
    assert isinstance(step, RepeatStep)
    assert step.id == "collect"
    assert step.times == 3
    assert step.action.type == "http.fetch"
    assert step.emit.mappings["items"] == {"merge": "append", "value": "${steps.collect.result.body}"}


def test_parse_repeat_with_interpolated_times():
    text = """
version: "1.0"
name: "dyn_loop"
steps:
  - id: loop_step
    repeat:
      times: "${input.count}"
      do:
        action: file.read
        args:
          path: /workspace/file.txt
    emit: {}
"""
    spec = parse(text)
    step = spec.steps[0]
    assert isinstance(step, RepeatStep)
    assert step.times == "${input.count}"


def test_parse_multiple_steps():
    text = """
version: "1.0"
name: "multi"
steps:
  - id: step_one
    do:
      action: file.read
      args:
        path: /workspace/a.txt
    emit:
      content: "${steps.step_one.result.content}"
  - id: step_two
    do:
      action: file.write
      args:
        path: /workspace/b.txt
        content: "${emit.content}"
    emit: {}
"""
    spec = parse(text)
    assert len(spec.steps) == 2
    assert spec.steps[0].id == "step_one"
    assert spec.steps[1].id == "step_two"


# ── Invalid input — ParseError expected ──────────────────────────────────────


def test_parse_invalid_yaml():
    with pytest.raises(ParseError, match="YAML parse error"):
        parse(": : :\n  bad: [unclosed")


def test_parse_not_a_mapping():
    with pytest.raises(ParseError, match="YAML mapping"):
        parse("- just a list item")


def test_parse_missing_name():
    with pytest.raises(ParseError, match="'name'"):
        parse('version: "1.0"\nsteps: []')


def test_parse_missing_version():
    with pytest.raises(ParseError, match="'version'"):
        parse('name: "test"\nsteps: []')


def test_parse_step_without_do_condition_or_repeat():
    text = """
version: "1.0"
name: "bad"
steps:
  - id: orphan
    unknown_key: value
"""
    with pytest.raises(ParseError, match="'do', 'condition', 'repeat'"):
        parse(text)


def test_parse_step_id_with_hyphen_rejected():
    text = """
version: "1.0"
name: "bad_id"
steps:
  - id: my-step
    do:
      action: file.read
      args:
        path: /workspace/x.txt
    emit: {}
"""
    with pytest.raises(ParseError, match="not a valid identifier"):
        parse(text)


def test_parse_do_with_non_dict_args():
    text = """
version: "1.0"
name: "bad_args"
steps:
  - id: bad_step
    do:
      action: file.read
      args: "not a mapping"
    emit: {}
"""
    with pytest.raises(ParseError, match="'do.args' must be a mapping"):
        parse(text)


def test_parse_repeat_missing_times():
    text = """
version: "1.0"
name: "no_times"
steps:
  - id: loop
    repeat:
      do:
        action: file.read
        args:
          path: /workspace/x.txt
    emit: {}
"""
    with pytest.raises(ParseError, match="'repeat.times' is required"):
        parse(text)


def test_parse_repeat_missing_do():
    text = """
version: "1.0"
name: "no_do"
steps:
  - id: loop
    repeat:
      times: 3
    emit: {}
"""
    with pytest.raises(ParseError, match="'repeat.do' is required"):
        parse(text)
