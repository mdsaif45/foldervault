fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let mut res = winres::WindowsResource::new();
    // id 1 = app icon (padlock), id 2 = locked-folder icon used by the .fvlt
    // file association (referenced from the registry as "<exe>,-2").
    res.set_icon_with_id("../../assets/app.ico", "1");
    res.set_icon_with_id("../../assets/locked-folder.ico", "2");
    res.set("FileDescription", "FolderVault");
    res.set("ProductName", "FolderVault");
    res.set_manifest(
        r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0" processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>"#,
    );
    res.compile().expect("embed resources");
    println!("cargo:rerun-if-changed=../../assets/app.ico");
    println!("cargo:rerun-if-changed=../../assets/locked-folder.ico");
}
