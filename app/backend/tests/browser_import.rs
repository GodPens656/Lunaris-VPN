use lunaris_backend::subscriptions;

#[test]
fn import_survives_browser_url_normalization_without_changing_signed_tokens() {
    let url = "https://sub.example/a%2Fb?token=a%26b%2Bc&mode=1";
    let original = format!("lunaris://import://{url}");
    let browser_url = url::Url::parse(&original).unwrap().to_string();
    assert_eq!(browser_url, format!("lunaris://import//{url}"));
    let encoded: String = url::form_urlencoded::byte_serialize(url.as_bytes()).collect();
    for prefix in [
        "lunaris://import://",
        "lunaris://import//",
        "LUNARIS://IMPORT://",
        "LUNARIS://IMPORT//",
    ] {
        for value in [url, encoded.as_str()] {
            assert_eq!(
                subscriptions::subscription_url(&format!("{prefix}{value}")).unwrap(),
                url
            );
        }
    }
    assert_eq!(subscriptions::subscription_url(&browser_url).unwrap(), url);
}

#[test]
fn normalized_import_keeps_url_validation() {
    for value in [
        "file:///etc/passwd",
        "https://user:password@example.com/sub",
        "https://example.com/sub#fragment",
        "https://example.com:bad/sub",
        "https://example.com/sub\n",
    ] {
        assert!(subscriptions::subscription_url(&format!("lunaris://import//{value}")).is_err());
    }
    assert!(subscriptions::subscription_url("lunaris://import/https://example.com/sub").is_err());
    assert!(subscriptions::subscription_url(&format!("lunaris://import//{}", "a".repeat(25000))).is_err());
}
