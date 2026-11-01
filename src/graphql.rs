//! GraphQL allowlist: one `query` operation, top-level fields from a fixed list, nothing else.

use graphql_parser::query::{Definition, OperationDefinition, Selection, parse_query};

pub fn check(body: &[u8], allowed: &[String]) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "body is not JSON".to_string())?;
    let obj = v.as_object().ok_or("body is not a JSON object")?;
    if let Some(k) = obj
        .keys()
        .find(|k| !matches!(k.as_str(), "query" | "variables" | "operationName"))
    {
        return Err(format!("unexpected key {k:?}"));
    }
    let q = obj
        .get("query")
        .and_then(|q| q.as_str())
        .ok_or("no query string")?;
    let doc = parse_query::<&str>(q).map_err(|_| "query does not parse".to_string())?;
    let [def] = doc.definitions.as_slice() else {
        return Err("exactly one operation, no fragments".into());
    };
    let set = match def {
        Definition::Operation(OperationDefinition::Query(q)) => &q.selection_set,
        Definition::Operation(OperationDefinition::SelectionSet(s)) => s,
        Definition::Operation(OperationDefinition::Mutation(_)) => {
            return Err("mutations are not allowed".into());
        }
        Definition::Operation(OperationDefinition::Subscription(_)) => {
            return Err("subscriptions are not allowed".into());
        }
        Definition::Fragment(_) => return Err("fragments are not allowed".into()),
    };
    if set.items.is_empty() {
        return Err("empty query".into());
    }
    for item in &set.items {
        match item {
            Selection::Field(f) if allowed.iter().any(|a| a == f.name) => {}
            Selection::Field(f) => return Err(format!("field {:?} is not allowed", f.name)),
            _ => return Err("fragments are not allowed".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(q: &str) -> Result<(), String> {
        check(
            serde_json::json!({"query": q, "variables": {"id": "x"}})
                .to_string()
                .as_bytes(),
            &["gpuTypes".to_string()],
        )
    }

    #[test]
    fn allows_listed_queries() {
        ok("query($id: String) { gpuTypes(input: {id: $id}) { id displayName securePrice communityPrice } }").unwrap();
        ok("{ gpuTypes { id } }").unwrap();
        ok("query Q { a: gpuTypes { id } }").unwrap();
    }

    #[test]
    fn denies_everything_else() {
        for q in [
            "mutation { podTerminate(input: {podId: \"x\"}) }",
            "mutation { gpuTypes { id } }",
            "subscription { gpuTypes { id } }",
            "{ myself { id } }",
            "{ gpuTypes { id } myself { pubKey } }",
            "{ ...F } fragment F on Query { gpuTypes { id } }",
            "{ ... on Query { myself { id } } }",
            "query A { gpuTypes { id } } query B { myself { id } }",
            "{ __schema { types { name } } }",
            "not graphql",
        ] {
            assert!(ok(q).is_err(), "allowed: {q}");
        }
        let allowed = ["gpuTypes".to_string()];
        assert!(check(b"[]", &allowed).is_err());
        assert!(
            check(
                b"{\"query\": \"{ gpuTypes { id } }\", \"extensions\": {}}",
                &allowed
            )
            .is_err()
        );
    }
}
