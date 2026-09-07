# Prüfplan des externen Testlabors

Ziel ist ein Plugin, das im Dauerbetrieb keinen Schaden anrichtet: keine vertraulichen Werte hinaus, keine verfälschten Befehle zurück, kein Blockieren gültiger Anfragen, kein Datenverlust im Stream. Was geprüft ist und was dabei herauskam, steht in [BEFUNDE.md](BEFUNDE.md); diese Datei sagt, wo was liegt und was noch fehlt, damit eine Sitzung ohne Vorgeschichte weitermachen kann.

Der Stand zum 7. September: neunzehn Befunde aus 227 Proben in sieben Paketen, elf davon mit Leckwirkung. Einundvierzig Tests sind rot und sollen es bleiben, bis die Befunde behoben sind. Die sechs Bereiche, die dieser Plan ursprünglich als offen führte, sind abgearbeitet.

---

# Wie hier gearbeitet wird

Jeder Prüfbereich hat ein eigenes Unterverzeichnis mit eigenem Go-Paket. Das ist keine Förmlichkeit: liegen zwei Arbeiten im selben Paket, genügt eine doppelte Hilfsfunktion, und der Bau schlägt für beide fehl. Die gemeinsamen Helfer stehen in [lab/lab.go](lab/lab.go) und werden als `privacyfilter-testlab/lab` importiert; die Tests der ersten Runde liegen flach im Wurzelpaket und bleiben dort.

Erreichbar sind von hier `detect`, `pseudo`, `mapping` und `payload`. Nicht erreichbar sind der Interceptor, `stream.go`, der Lader der Term-Datei, die Prüfung der Konfiguration und das Prüfprotokoll, weil sie in `package main` liegen, und `internal/*` sperrt Go ohnehin. Was dort geprüft werden soll, wird nachgebaut und als Nachbau gekennzeichnet.

Erlaubt sind `go build`, `go test`, `go vet`, `go mod tidy` und `gofmt`, und geschrieben wird ausschließlich unterhalb von `testlab/`. Der Klon daneben wird nicht angefasst; dort arbeitet eine andere Sitzung.

Ein Wert, auf den es ankommt, wird zur Laufzeit aus Zahlen zusammengesetzt und nicht als Literal geschrieben. Jede Datei dieses Verzeichnisses läuft auf ihrem Weg auf die Platte selbst durch den Filter, und ein Literal kann dort als etwas anderes ankommen. `lab.V4` und `lab.MAC` sind dafür da. Aus derselben Ursache ist ein Verzeichnisname in einem Befehl unzuverlässig: `go test ./...` mit `-run` über den Testnamen führt sicher zum Ziel, ein getippter Paketpfad nicht immer.

Ein Test, der einen Fehler zeigt, bleibt rot. Ein Test, der Verhalten festhält, über das noch zu entscheiden ist, bleibt grün und protokolliert mit `t.Logf`. Wer einen Befund findet, schreibt ihn in [BEFUNDE.md](BEFUNDE.md): was passiert, unter welchen Umständen, wie schwer es wiegt, wo der Test steht, welche Kur vorgeschlagen wird.

---

# Was in den Paketen liegt

Das Wurzelpaket trägt die erste Runde: Round-Trip und Tokengrenzen, Unicode, die Formen des Systembetriebs, den Alltag einer Sitzung mit Patch und `old_string`, Adressbereiche, Nebenläufigkeit, Maßstab, die Formtreue je Art und den Ersatzwert, der im Gesprächsverlauf hängen bleibt.

`stream` baut den Ablauf des Streams in `rebuild.go` nach der Vorlage von `stream.go` nach und prüft Ereignisfolgen, Rückhalte über Blockgrenzen, Abbrüche und Werkzeugfragmente. `layers` prüft das Zusammenspiel der Erkennungsschichten samt der Vorschicht, die Mailadressen befördert. `jsonedge` prüft die JSON-Ebene an ihren Rändern und die Sperrliste an Orten, an die sie nicht gehört. `props` hält zehn Fuzz-Ziele mit Korpus für die Eigenschaften, die über zufälligen Eingaben gelten müssen. `harm` prüft, was ein Originalwert anrichtet, wenn er in Befehle, Patches, Konfigurationszeilen und Suchmuster gerät. `config` prüft die Konstruktoren gegen fehlerhafte Konfiguration.

Ausführen mit `cd testlab && go test -race ./...`. Ein Fuzz-Lauf über das Erwartete hinaus geht mit `-run Fuzz -fuzz FuzzPropsRoundTripAnyTerm -fuzztime 60s` auf das Paket `props`.

---

# Was offen bleibt

Der Weg durch den echten HTTP-Pfad ist von außen nicht zu prüfen und damit der nächste Schritt für jemanden, der im Klon arbeiten darf: ob `on_error: block` bei einem fehlerhaften Body wirklich blockt, ob die Grenze von zweiunddreißig Megabyte greift, was ein mitten im Stream abgebrochener Anbieter mit dem zurückgehaltenen Rest macht, ob das Prüfprotokoll schreibt, was es schreiben soll, und ob der Host einen fehlerhaften Chunk unverändert weiterreicht und einen unterdrückten wirklich unterdrückt. Dazu die Nebenläufigkeit eines Streamzustands unter den Aufrufen des Hosts, die der Nachbau nicht abbildet.

Ungeprüft sind ferner betterleaks hinter seinem Build-Tag und alles, was nicht dem Anthropic-Schema folgt. Die Race beim Neuladen der Konfiguration im laufenden Host bleibt eine Frage für das lebende System; die Nebenläufigkeit der Bausteine ist geprüft und hält.

Was die Befunde selbst angeht, liegt die Reihenfolge im ersten Kapitel des Berichts. Sie beginnt mit sieben Kuren von je einer Zeile und endet bei drei Entscheidungen, die jemand treffen muss, der das Plugin verantwortet.
