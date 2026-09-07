# Befunde aus dem externen Testlabor

Neunzehn Befunde aus 227 Proben gegen den Stand vom 7. September, elf davon mit Leckwirkung, zwei mit Wirkung auf die Kommandozeile und einer, der sich selbst nährt. Die Tests liegen bewusst außerhalb des Klons, in `testlab/` neben dem Repository, damit die laufende Arbeit im Repo nichts abbekommt: ein eigenes Go-Modul mit `replace` auf den Klon, das `detect`, `pseudo`, `mapping` und `payload` von außen anspricht. `internal/*` bleibt von dort unerreichbar, `stream.go` und der Interceptor ebenfalls, weil sie `package main` sind; der Rückhalt des Streams wurde deshalb über `mapping.Restorer` nachgebildet, und der Nachbau entspricht Zeile für Zeile dem, was `stream.go` tut.

Ausführen mit `cd testlab && go test -race ./...`. Einundvierzig Tests sind rot, und sie sollen rot bleiben, bis die Befunde behoben sind. Die übrigen 186 decken Round-Trip, Tokengrenzen, Idempotenz in beide Richtungen, überlappende Terme, Regex-Metazeichen als Literale, die Zahlenschreibweise, die Verschachtelungstiefe bis 5000 Ebenen, den SSE-Parser mit CRLF und ohne Leerzeichen nach `data:`, die doppelte Kodierung in `partial_json` mit Anführungszeichen, Backslash und Emoji sowie Bodies mit umgebendem Leerraum ab. Dazu die Formen des Systembetriebs: derselbe Rechnername in dreizehn Befehlszeilen, Adressen mit Port, Präfixlänge und IPv6-Klammern, Konfigurationszeilen in YAML, INI, JSON, systemd und `/etc/hosts`. Dazu der Alltag einer Sitzung: ein Patch, der hinterher noch passt, ein Fragment als `old_string`, Compilermeldungen mit Zeile und Spalte, und die Frage, was von einem Ersatzwert übrig bleibt, wenn das Modell ihn nicht wörtlich wiederholt. Dazu die Sperrliste an einem Body in der Gestalt des echten, sechzehn Schreibweisen eines Pfades, der Namensraum unter Kollisionsdruck und die Ableitung des Salts. Und schließlich Nebenläufigkeit und Maßstab. Der Fehler, der neue Dateien unter einem Ersatznamen anlegte, ist am laufenden System bestätigt behoben.

Eine Warnung zur Arbeitsweise in diesem Verzeichnis: jede Testdatei läuft auf ihrem Weg auf die Platte selbst durch den Filter. Eine Adresse, die als Literal im Quelltext steht, kann dort als etwas anderes ankommen, und aus einer Ausgabe kopierte Werte sind Ersatzwerte, keine Beispiele. Werte, auf die es ankommt, deshalb zur Laufzeit aus Zahlen zusammensetzen, wie es `ranges_test.go` tut; nur so ist die Probe das, was sie zu sein vorgibt.

---

# Reihenfolge der Kuren

Was vor dem produktiven Einsatz weg muss, ist nicht die längste Liste, sondern die kurze: nur zwei Befunde können aktiv Schaden anrichten, und beide stehen im Kapitel über die Sonderzeichen im Originalwert. Ein Wagenrücklauf zeigt in der Rückfrage einen anderen Befehl an, als ausgeführt wird, und ein Zeilenumbruch oder ein Semikolon im Wert verwandelt eine Zeile in zwei. Solange die Term-Liste keinen Wert mit Steuerzeichen, Anführungszeichen, Semikolon, Prozentzeichen oder Schrägstrich enthält, ist dieser Weg zu. Das ist heute eine Frage der Disziplin und sollte eine Prüfung beim Laden werden; bis dahin ist die Liste durchzusehen. Alles andere in diesem Bericht lässt Daten hinaus oder verliert Text — schlimm genug, aber es zerstört nichts auf einem Server.

Zuerst die sieben Kuren, die je eine Zeile sind und keine Entscheidung verlangen: das Doppelkreuz im Term und das Byte Order Mark im Lader, `signature` an den Blocktyp gebunden, der gepunktete Sperrschlüssel elementweise verglichen, die Endung eines Dateinamens nach ihrer Form geprüft statt einfach behalten, die Sperrregeln an ihren Ort statt an den Schlüsselnamen gebunden, und der Werkzeugname überall gleich behandelt. Alle sieben treffen jeden Nutzer, alle sieben haben einen Test. Die letzten zwei wiegen im Alltag mehr als sie kosten: die Argumente eines Werkzeugaufrufs sind der Ort, an dem ein Systemadministrator seine Werte hinschickt, und ein halb ersetzter Werkzeugname macht die Anfrage kaputt.

Dann die drei Lecks, die eine Entscheidung brauchen. Der Ersatzraum für IPv4 und MAC verlangt eine Zahl, nämlich wie eng er wird, und ändert die Ersatzwerte bestehender Sitzungen; er erledigt zugleich den Weg, auf dem ein ausgeschlossener Treffer sein ganzes Token abschirmt. Der Teiltreffer verlangt, die Vorschicht `promoteAddresses` von Mailadressen auf jede Art zu verallgemeinern. Die Schlüsselnamen im JSON verlangen, den Rundgang auch über sie zu führen, und das ist die aufwendigste der drei. Alle drei sind aber die, die im Alltag eines Systemadministrators wirklich greifen, denn Werkzeugausgaben schlüsseln nach Namen und Verzeichnisse tragen Kunde und Vorgang im selben Wort.

Danach die Verfälschungen. Der Stream braucht zwei Handgriffe: den Rückhalt beim Fehlerereignis ausspülen und die Rückhalte eines Chunks erst festschreiben, wenn alle seine Ereignisse durch sind. Der fehlende Rückhalt am Ende eines vollständigen Ersatzwertes und das einzelne Surrogat sind eng umrissen und haben je einen roten Test. Der Ersatzwert, der im Gesprächsverlauf hängen bleibt, ist der einzige Befund, dessen Schaden lokal entsteht; die vorgeschlagene Kur, die Zuordnung an die Sitzung statt an die Anfrage zu binden, erledigt die Frist der Tabelle gleich mit, und beides zusammen zu entscheiden spart die halbe Arbeit.

Der Rest ist Härtung und kann warten: Wortgrenzen für Regex-Terme, die fünf Prüfungen an der Konfiguration, die Adressmuster in längeren Zahlenketten, die Lücken im Netz der Pfadebene, die Versalschrift mit SS. Unter den Konfigurationspunkten lohnt der Blick auf die Rechte der Schlüsseldatei zuerst, denn aus dem Salt-Schlüssel lassen sich alle Ersatzwerte einer Sitzung nachrechnen.

---

# Ein Teiltreffer hebelt das Sicherheitsnetz aus

Liegt ein Treffer einer früheren Schicht ganz innerhalb eines Treffers einer späteren, gewinnt der kürzere und der Rest des längeren bleibt im Klartext stehen. Ein Term, der nur einen Teil eines Verzeichnisnamens trifft, verhindert damit, dass die Pfadebene das ganze Segment ersetzt: aus einem Verzeichnis, das nach Kunde und Vorgang benannt ist, geht der Vorgangsteil hinaus. Dasselbe innerhalb einer Adresse, eines Netzes, einer URL, einer IBAN und eines Fingerabdrucks — der Term bricht sie auf und ihr Schwanz bleibt sichtbar.

Die Folge ist paradox und deshalb leicht zu übersehen: ein Eintrag in der Term-Liste macht den Schutz schlechter, als hätte man ihn weggelassen. Wer „kunde“ einträgt, verliert den Schutz für „kundenakte-4711“, den die Pfadebene mit `replace_unknown` von sich aus geboten hätte.

Der zweite Weg dorthin führt über die Abschirmung. Ein ausgeschlossener Treffer — eine Adresse in Ersatzwertform, die das Composite bewusst nicht anfasst — schirmt seine Stelle gegen spätere Schichten ab, und das ist richtig so. Steckt er aber in einem längeren Token, schirmt er das ganze Token mit ab: ein Verzeichnis, das nach Kunde und Knotenadresse benannt ist, wird nicht ersetzt, weil die Adresse darin für einen Ersatzwert gehalten wird. Mit dem Kapitel über die Ersatzadressen zusammen wird daraus ein Weg, auf dem ein Tailscale-Netz die Pfadebene stilllegt.

Für Mailadressen ist die Regel im Klon inzwischen gelöst: eine Vorschicht `promoteAddresses` lässt die umschließende Adresse gewinnen. Die Lösung ist auf `KindEmail` beschränkt; für jede andere Art gilt sie nicht.

Reproduktion: `TestLayers_TermInsideAnUnknownSegmentUncoversTheRest`, `TestLayers_TermInsideAnAddressBreaksItApart` und `TestLayers_AnExcludedHitShieldsTheSegmentAroundIt`, alle drei rot. `TestLayers_EarlierLayerWinsOverTheLongerLaterMatch` und `TestLayers_PromotionIsLimitedToMailAddresses` halten die geltende Regel und die Grenze der bestehenden Lösung grün fest.

Vorschlag: die Regel aus `promoteAddresses` von `KindEmail` auf jeden Treffer verallgemeinern, der einen nicht ausgeschlossenen Treffer einer früheren Schicht ganz enthält — der umschließende gewinnt, der ausgeschlossene schirmt weiter ab. Den zweiten Weg löst nicht die Abschirmung, sondern der engere Ersatzraum aus dem Kapitel über die Ersatzadressen; eine Kur deckt dann beide.

---

# Ein Wert als JSON-Schlüssel geht unberührt hinaus

Der Rundgang durch den Body besucht Werte, nie Schlüsselnamen. Steht ein Rechnername, ein Kundenname oder ein Pfad als Schlüssel, geht er im Klartext hinaus. Das ist keine ausgedachte Form, sondern die Form, in der Werkzeuge antworten: `docker inspect` schlüsselt nach Container- und Netzwerknamen, `kubectl get -o json` nach Ressourcennamen, `terraform show -json` nach Adressen der Ressourcen, eine `package.json` nach Paketnamen, jede Zuordnung von Rechner zu Zustand nach dem Rechner.

Die Rückrichtung ist genauso betroffen, und dort wird der Schaden lokal. Schreibt das Modell einen Ersatzwert als Schlüssel — in den Argumenten eines Werkzeugaufrufs etwa, `{"files":{"<Ersatzwert>":"Inhalt"}}` —, wird er nicht wiederhergestellt, und das Werkzeug arbeitet mit dem Ersatzwert weiter. Das ist derselbe Weg, auf dem gestern eine Datei unter einem Ersatznamen entstand, nur eine Ebene tiefer.

Reproduktion: `TestJSONEdge_ObjectKeysAreNeverVisited`, rot, mit beiden Richtungen als Unterprobe.

Vorschlag: Schlüsselnamen auf dem Hinweg wie Werte behandeln und auf dem Rückweg wie Werte wiederherstellen. Das ist mehr als eine Zeile, weil ein Schlüssel Struktur trägt und ein Umbenennen zwei Schlüssel zusammenfallen lassen kann; die Ersatzwerte sind aber injektiv, solange die Tabelle es ist, und der Fall zweier Werte, die auf denselben Ersatzwert fallen, ist bereits ausgeschlossen. Wer den Aufwand nicht will, deckt zumindest die Argumente von Werkzeugaufrufen ab, weil dort der lokale Schaden entsteht.

---

# Wo die Ersatzadressen wohnen, wohnen auch echte

Der Ersatzwert für eine IPv4-Adresse liegt in 100.64.0.0/10, der für eine MAC beginnt mit `02`. Beide Räume sind in Betrieb. Aus 100.64.0.0/10 geben Tailscale und Headscale ihren Knoten die Adressen, und Provider teilen daraus ihren Kunden hinter CGNAT zu; mit `02` beginnt jede MAC, die Docker einem Container und seiner Brücke gibt. Der Schutz gegen doppelte Ersetzung prüft allein die Form: `Generator.IsPseudonym` bejaht jede Adresse aus diesem Bereich, gleich ob sie aus der Tabelle stammt oder aus dem Netz des Nutzers, und das Composite reicht sie daraufhin unverändert durch.

Für einen Selbsthoster mit Tailscale ist das der schwerste Befund des Labors: die Adressen seiner eigenen Knoten sind genau die, die er schützen will, und genau die, die der Filter für seine eigenen hält. Für jede `docker inspect`-Ausgabe gilt dasselbe.

Bei IPv6 ist es anders und richtig gelöst. Die Ersatzadressen liegen unter einem festen 48-Bit-Präfix im ULA-Bereich, und geprüft wird dieses Präfix, nicht der ganze Bereich; eine gewöhnliche ULA-Adresse aus einem Heimnetz wird deshalb ersetzt. Was für IPv6 gilt, fehlt für IPv4 und für MAC.

Reproduktion: `TestRange_RealValuesInsideThePseudonymSpace`, rot für Tailscale-Knoten, CGNAT-Adresse und Docker-MAC, grün für ULA und für eine gewöhnliche private Adresse.

Vorschlag: den Ersatzraum verengen, wie bei IPv6 schon geschehen — ein festes /16 innerhalb 100.64.0.0/10 und ein festes 24-Bit-Präfix für MAC senken die Kollision von allem auf ein Tausendstel, ohne die Formtreue anzutasten. Das Exclude stattdessen an die Tabelle zu binden, löst die Kollision ganz, nimmt aber den Schutz für Pseudonyme aus früheren Anfragen desselben Gesprächs, deren Tabelle abgelaufen ist: die würden ein zweites Mal ersetzt und wären auf dem Rückweg nicht mehr aufzulösen. Deshalb zuerst der engere Raum, und ein Konfigurationsschlüssel für den, dessen Netz dennoch hineinragt.

---

# Die Endung eines Dateinamens bleibt stehen, was auch darin steht

Der Ersatzwert für einen Dateinamen behält die Endung, damit das Modell weiterhin sieht, womit es zu tun hat. Als Endung gilt alles hinter dem letzten Punkt. Trägt ein Dateiname dort keine Endung, sondern einen Kundennamen oder eine Vorgangsnummer, geht sie unberührt hinaus: aus einem Bericht, der nach der Firma benannt ist, wird ein Ersatzwert mit der Firma daran, und aus einem Export mit Projektnummer ein Ersatzwert mit der Projektnummer.

Reproduktion: `TestHarm_FileNamePseudonymCarriesTheSuffix`, rot, mit einer gewöhnlichen Endung als grüner Gegenprobe.

Vorschlag: nur behalten, was als Dateiendung durchgeht — höchstens fünf Zeichen, nur Buchstaben und Ziffern, keine Unterstriche, kein Bindestrich —, und alles andere mitersetzen. Wer es genauer will, prüft gegen eine Liste der Endungen, die im Alltag vorkommen; die Prüfung nach Form deckt die Fälle ab, auf die es ankommt.

---

# Die Term-Liste verliert Werte beim Laden

Zwei Stellen, an denen ein Term als etwas anderes ankommt, als er in der Datei steht, und beide enden im Klartext.

`termsfile.go:73` schneidet jede Zeile am ersten `#` ab, solange sie nicht mit `{` beginnt. Ein Wert mit Doppelkreuz wird damit halbiert: aus `Projekt#42` wird der Term `Projekt`, und `#42` steht danach ungeschützt im Text. Doppelkreuze kommen in Projekt- und Vorgangsnummern, in Raumbezeichnungen und in Verzeichnisnamen vor. Ein Kommentarzeichen braucht die Datei, aber es sollte nur am Zeilenanfang gelten oder durch `\#` aufhebbar sein.

Die zweite Stelle ist das Byte Order Mark. `strings.TrimSpace` entfernt U+FEFF nicht, weil es kein Leerraumzeichen ist. Wer die Liste unter Windows oder mit einem Editor pflegt, der eine Signatur schreibt, hat als ersten Term eine Zeichenkette, die auf nichts passt — und merkt es nicht, weil nichts protokolliert wird. Ein `strings.TrimPrefix` auf das erste Byte-Tripel der Datei genügt.

Reproduktion: `TestTerm_TruncatedAtHash` und `TestTerm_ByteOrderMark`. Der Lader selbst liegt in `package main` und ist von außen nicht ladbar; die Tests zeigen die Wirkung auf der Detektorebene, die Ursache steht in der genannten Zeile.

---

# Ein Ersatzwert im Gesprächsverlauf ist für immer einer

Kommt ein Ersatzwert einmal unaufgelöst beim Client an, wird er dort gewöhnlicher Text, und von da an gibt es keinen Weg zurück. Der Hinweg der nächsten Anfrage überspringt ihn, weil das Composite alles ausschließt, was wie ein Ersatzwert aussieht; er wird also nicht in die neue Tabelle eingetragen; also findet der Rückweg nichts, womit er ihn auflösen könnte. Der Fehler nährt sich selbst, und er wächst mit jeder Anfrage, in der das Modell den Wert wiederholt.

Das ist keine Theorie. In dieser Sitzung schlug ein Befehl fehl, weil an der Stelle eines Verzeichnisnamens ein Ersatzwert stand; dieselbe Ursache steckt hinter der Datei, die gestern unter einem Ersatznamen angelegt wurde. Der lokale Schaden ist größer als der entfernte: was das Modell schreibt, wird ausgeführt und auf die Platte geschrieben.

In den Verlauf gerät ein Ersatzwert auf drei Wegen, und alle drei sind in diesem Labor belegt: die Tabelle ist abgelaufen oder verdrängt, das Modell hat den Ersatzwert verändert — gekürzt, umbrochen, mit einem Leerzeichen versehen —, oder der Wert kam in der aktuellen Anfrage nur als Ersatzwert vor und nirgends im Klartext.

Reproduktion: `TestCarry_PseudonymInTheHistoryIsNotResolvable` zeigt die leere zweite Tabelle und den Ersatzwert, der beim Client ankommt; `TestCarry_WaysIntoTheHistory` hält die drei Wege fest, `TestCarry_SameTableStillResolves` die Gegenprobe.

Vorschlag: die Zuordnung an die Sitzung binden statt an die Anfrage. Der Salt ist ohnehin pro Gespräch abgeleitet und die Erzeugung deterministisch; eine Tabelle, die für die Dauer der Sitzung lebt und beim Rückweg konsultiert wird, löst alle drei Wege auf einmal und macht die Frist aus dem übernächsten Kapitel gleich mit erledigt. Der Preis ist Speicher, den der Maßstab-Abschnitt beziffert, und eine Antwort auf die Frage, wann eine Sitzung endet.

---

# Der Schlüssel signature sperrt mehr als den Denkblock

`signature` steht als Schlüsselname in der Sperrliste, unabhängig davon, in welchem Block er auftaucht. Gemeint ist die Signatur des Denkblocks, die an Text und Gesprächspräfix gebunden ist und deshalb unangetastet bleiben muss. Getroffen wird jedes Feld dieses Namens: die Fußzeile, die ein Mail-Werkzeug unter `signature` zurückgibt, die Zeile `Good signature from …` aus einer Commit-Prüfung, ein PDF-Feld. Was dort steht, geht ungefiltert hinaus.

Reproduktion: `TestDeny_SignatureOutsideThinking`, rot für die drei Fremdverwendungen, grün für die Signatur im Denkblock, die unangetastet bleiben muss.

Vorschlag: `signature` an den Blocktyp binden, so wie `name` schon an `ToolNameParents` gebunden ist — gesperrt innerhalb eines Blocks mit `type: thinking` oder `redacted_thinking`, sichtbar überall sonst. Die Sperrliste hat die Maschinerie dafür bereits.

---

# Das Netz der Pfadebene greift nur bei absoluten Pfaden

Die Pfadebene mit `replace_unknown` ist das Sicherheitsnetz für das Verzeichnis, das niemand in die Term-Liste eingetragen hat. Sie greift bei absoluten Pfaden, bei `./` und bei `~/`. Sie greift nicht beim relativen Pfad ohne führenden Punkt, und das ist die Schreibweise, in der Werkzeuge ihre Ausgaben machen: `git status`, `go build`, jede Compilermeldung. Ebenso wenig bei `$HOME/…`, bei Windows-Pfaden mit Rückstrich, bei UNC-Pfaden und bei Pfaden in `file://`- und `http://`-Adressen.

Für ein Verzeichnis, das in der Term-Liste steht, ist das folgenlos — die Term-Ebene findet es in jeder Schreibweise. Die Lücken zählen genau dort, wo das Netz gebraucht wird, nämlich beim vergessenen Eintrag.

Reproduktion: `TestPath_NetGapsForUnknownDirectories` führt zwölf Schreibweisen vor und benennt die neun, die durchgehen. `TestPath_ShapesRoundTrip` zeigt, dass die erkannten Formen sauber zurückkommen, doppelte Schrägstriche und Umlaute eingeschlossen.

Vorschlag: den relativen Pfad ohne Punkt aufnehmen, sobald er mindestens einen Schrägstrich und ein bekanntes Endsegment hat, und die Pfade in `file://`-Adressen mitnehmen. Windows und UNC sind eine Frage der Zielgruppe. Dass ein Verzeichnisname als bloßes Wort im Fließtext stehen bleibt, ist dagegen richtig so: dafür ist die Term-Ebene da.

---

# Die Sperrliste urteilt nach dem Schlüsselnamen, nicht nach dem Ort

Die Argumente eines Werkzeugaufrufs sind ein freies Objekt: welche Schlüssel darin stehen, bestimmt das Werkzeug, nicht die API. Die Sperrliste prüft aber Schlüsselnamen, wo sie auch stehen. Ein Werkzeug, dessen Argumente `id`, `type`, `model`, `role`, `media_type`, `stop_reason`, `tool_use_id` oder `cache_control` heißen — Namen, die jedes zweite Werkzeug verwendet —, schickt seine Werte im Klartext hinaus. Von elf geprüften Argumenten bot der Rundgang genau eines an; zehn blieben unberührt, weil ihr Schlüssel wie ein Feld des Schemas heißt.

Schärfer wird es beim Blocktyp. Trägt ein Werkzeugargument den Schlüssel `type` mit dem Wert `thinking`, wird das ganze Argumentobjekt für einen Denkblock gehalten und mitsamt seinen Nachbarn ausgenommen. Ein einzelnes Argument schaltet damit den Schutz für die anderen ab.

Und die beiden Richtungen widersprechen sich, wenn ein Objekt zwei `type`-Schlüssel trägt. Der Hinweg liest über den JSON-Dekodierer den letzten, der Rückweg über seinen Byte-Scanner den ersten. Ein Block, der als Text beginnt und als `thinking` endet, wird auf dem Hinweg ausgenommen und auf dem Rückweg als Text behandelt — sein Inhalt geht unberührt hinaus. Doppelte Schlüssel sind nach der Norm undefiniert und im Alltag selten; hier sind sie ein Weg.

Reproduktion: `TestJSONEdge_DenyRulesReachIntoToolArguments`, `TestJSONEdge_ObjectOfOnlyDeniedKeys` und `TestJSONEdge_DuplicateTypeKeyDecidesTheDenyList`, alle rot, dazu `TestJSONEdge_DuplicateKeyInOneObject` für den allgemeinen Fall doppelter Schlüssel, bei dem der Hinweg das erste Paar nie sieht und eine Ersetzung eines der beiden verliert.

Vorschlag: die Sperrregeln an ihren Ort binden, nicht an den Namen. Innerhalb von `tool_use.input` und `tool_result.content` gilt kein Schemafeld, denn dort schreibt das Werkzeug. Für den Blocktyp genügt, ihn nur dort zu lesen, wo ein Block stehen darf — als Element einer `content`-Liste —, und nicht in beliebigen Objekten. Und die beiden Richtungen sollten denselben Schlüssel lesen; welchen, ist zweitrangig, solange es derselbe ist.

---

# Ein Werkzeugname wird an einer Stelle ersetzt und an der anderen nicht

`tools[].name` ist gesperrt, damit das Modell den Namen unverändert sieht. `tool_choice.name` ist es nicht, ebenso nicht die Schlüssel unter `input_schema.properties`, die Einträge in `input_schema.required`, `mcp_servers[].name` und `container`. Enthält ein Werkzeugname einen Term, verweist die Anfrage danach auf ein Werkzeug, das es nicht gibt, und ein Schema verlangt eine Eigenschaft, die es nicht hat. Das ist kein Leck, sondern eine Anfrage, die der Anbieter ablehnt oder falsch beantwortet — und weil `on_error: block` nur den Hinweg schützt, nicht die Stimmigkeit des Bodys, fällt es erst beim Anbieter auf.

Reproduktion: `TestJSONEdge_FieldsTheAPIKnows`, rot, mit der Liste der besuchten Pfade im Protokoll.

Vorschlag: die Sperre von `tools[].name` auf alles ausweiten, was denselben Namen bezeichnet — `tool_choice.name`, `mcp_servers[].name`, `container` —, und die Schlüssel eines `input_schema` samt seiner `required`-Liste unangetastet lassen. Wer Werkzeugnamen schützen will, muss sie überall gleich behandeln; halb ersetzt ist schlechter als beides.

---

# Der Rückhalt des Streams geht verloren, und einmal geht er doppelt

Zwei Wege, auf denen der zurückgehaltene Text nicht dort landet, wo er soll.

Endet der Stream ohne `content_block_stop` und ohne `message_stop`, wird der Rückhalt nie ausgespült, und der Rest der Antwort erreicht den Client nie. Im Test sind es elf Byte, die Obergrenze liegt bei `MaxPseudonymLen` minus eins. Das trifft die abgerissene Verbindung ebenso wie ein `error`-Ereignis mitten im Stream, und ein `overloaded_error` ist im Betrieb nichts Seltenes. Das Plugin erkennt den Fall und schreibt eine Warnung, kann den Text aber nicht mehr ausliefern, weil der Host am Ende nichts mehr aufruft, in das sich Bytes schreiben ließen.

Der zweite Weg dreht es um. Die Ereignisse eines Chunks werden nacheinander abgearbeitet, und jedes Textstück schiebt seinen Schwanz sofort in den Rückhalt. Scheitert ein späteres Ereignis desselben Chunks, gibt die Verarbeitung einen Fehler zurück, und der Host liefert den Chunk unverändert aus — samt dem ersten Delta, dessen Schwanz schon im Rückhalt liegt. Derselbe Text geht damit zweimal hinaus, einmal roh und einmal aus dem Rückhalt, und der Ersatzwert bleibt in seiner rohen Hälfte beim Nutzer stehen.

Reproduktion: `TestStream_EndWithoutStopEventLosesHeldText` mit der abgerissenen Verbindung und dem Fehlerereignis als Unterproben, und `TestStream_PartialStateThenChunkError`; beide rot. Die Gegenprobe `TestStream_LoneMalformedEventPassesThrough` ist grün, ein einzelnes unlesbares Ereignis ohne vorherigen Rückhalt geht also richtig durch.

Vorschlag: den Rückhalt beim `error`-Ereignis ausspülen, so wie es vor `content_block_stop` und `message_stop` geschieht — das deckt den häufigeren der beiden Abbruchwege ab. Und die Rückhalte eines Chunks erst festschreiben, wenn alle seine Ereignisse durch sind, also auf einer Kopie arbeiten und sie am Ende übernehmen. Für die abgerissene Verbindung bleibt die Warnung, die schon steht.

---

# Nach zehn Minuten ist die Tabelle weg, auch mitten im Stream

Die Frist läuft ab dem Ablegen, nicht ab der letzten Nutzung. Eine Antwort, die länger als zehn Minuten streamt — langes Nachdenken, ein großer Patch, ein zäher Anbieter —, verliert ihre Tabelle mittendrin, und ab dieser Stelle kommt beim Nutzer an, was das Modell geschrieben hat: Ersatzwerte. Kein Datenabfluss, aber der Schaden ist trotzdem handfest, denn was das Modell in eine Datei schreibt, landet dann mit Ersatzwerten auf der Platte.

Reproduktion: `TestStore_TableExpiresWhileTheAnswerRuns` protokolliert den Verlust in Minute zehn, `TestStore_UseRefreshesTheDeadline` zeigt, dass neun Zugriffe die Frist nicht verlängern. Beide sind grün, sie halten das Verhalten fest.

Vorschlag: die Frist beim Zugriff auffrischen, was eine Zeile in `Get` ist, oder sie am Ende des Streams statt am Anfang der Anfrage bemessen. Die Verdrängung bei vollem Speicher hat dieselbe Schlagseite — sie nimmt die zuerst abgelegte Tabelle, und das ist bei einem langen Gespräch die noch laufende —, wiegt aber weniger, weil tausend Tabellen erst einmal zusammenkommen müssen. Immerhin protokolliert das Plugin diesen Fall bereits deutlich.

---

# Rückhalt hält wachsende Ersatzwerte zurück, entwertete nicht

Endet ein Chunk genau hinter einem vollständigen Ersatzwert und beginnt der nächste mit einem Buchstaben, einer Ziffer oder einem weiteren Ersatzwert, dann ersetzt der Stream, während derselbe Text am Stück unangetastet bleibt. Aus `h-936a9b4f6018` plus `x` wird gestreamt `zeus.lanx`, am Stück richtigerweise `h-936a9b4f6018x`, weil der Ersatzwert dort kein eigenes Token ist.

`Holdback` prüft, ob das Textende der Anfang eines Ersatzwertes sein könnte, also den Fall des Wachsens. Der zweite Fall fehlt: ein bereits vollständiger Ersatzwert am Textende kann durch das nächste Zeichen entwertet werden, und diese Entscheidung lässt sich erst treffen, wenn das Zeichen da ist. Es ist dieselbe Klasse wie der Fehler aus `54545e1`, nur die andere Richtung.

Reproduktion: `TestHoldback_CompletePseudonymAtChunkEnd` mit den Folgezeichen `x`, `1`, `h` und einem weiteren Ersatzwert; `TestHoldback_SplitAtEveryPosition` und `TestHoldback_ByteByByte` zeigen dasselbe beim Zerteilen an jeder Position. Der Gegentest `TestHoldback_DelimiterInNextChunk` ist grün: mit Leerzeichen, Punkt, Komma, Klammer, Zeilenumbruch oder am Textende stimmen beide Wege überein, ebenso beim Unterstrich, der seit `8436b9e` als Grenze gilt.

Vorschlag: endet der Text auf einem vollständigen Ersatzwert, diesen zurückhalten, bis das nächste Zeichen bekannt ist. Der Rückhalt bleibt dabei durch `MaxPseudonymLen` beschränkt, und das Blockende flusht bereits über `flushBefore`. Kein Leck, aber eine Textverfälschung und eine Abweichung zwischen den beiden Wegen, die die Testsuite an anderer Stelle sorgfältig ausschließt.

---

# Ein Punkt im Schlüsselnamen schaltet die Sperrliste scharf

Der Body `{"metadata.user_id":"flat-value","metadata":{"user_id":"nested-value"},"other":"plain"}` bietet dem Besucher nur `other` an. Der flache Schlüssel, der wörtlich `metadata.user_id` heißt, wird von der Regel für den verschachtelten Pfad erfasst, weil beide zur selben gepunkteten Form zusammengesetzt werden. Sein Wert wird also nie ersetzt und geht im Klartext hinaus.

Das ist der einzige Befund mit Leckwirkung. Sein Gewicht hängt daran, wie wahrscheinlich ein Schlüssel ist, der genau einer Pfadregel entspricht; flache Objekte mit gepunkteten Schlüsseln sind in Konfigurationen und Werkzeug-Argumenten alltäglich, ein Treffer auf `metadata.user_id` ist es nicht. Die Richtung stimmt allerdings ungünstig: die Konfusion führt immer zu mehr Ausschluss, nie zu mehr Ersetzung.

Reproduktion: `TestDeny_DottedKeyConfusion`. Der Gegentest für Teilbaum-Regeln, `TestDeny_DottedKeyConfusionSubtree`, ist grün, und `TestDeny_ToolUseInputName` bestätigt die feine Unterscheidung zwischen `tool_use.name` und `tool_use.input.name`.

Vorschlag: Pfade elementweise vergleichen statt über die zusammengesetzte Form, oder beim Zusammensetzen Punkte im Schlüsselnamen kennzeichnen. Der Fundort ist `DenyList.Denied` in `payload/deny.go`, Abschnitt „Dotted rule“.

---

# Ein einzelnes Surrogat wird zum Ersetzungszeichen

`{"keep":"\ud800","hit":"zeus.lan"}` kommt nach einer Ersetzung als `{"hit":"h-0123456789ab","keep":"�"}` zurück. Ein halbes Surrogatpaar ist gültiges JSON, hat aber keine UTF-8-Kodierung, und der Serialisierer ersetzt es. Ohne Ersetzung im Body passiert nichts, weil `Walk` dann die Originalbytes zurückgibt; sobald irgendwo ein Treffer liegt, wird der ganze Body neu geschrieben und die Stelle stillschweigend verändert.

Solche Sequenzen entstehen, wenn ein Werkzeug Text mitten in einem Zeichen abschneidet und der Client das als JSON kodiert. Selten, aber real, und die Änderung trifft Text, der mit dem Filter nichts zu tun hat.

Reproduktion: `TestWalk_LoneSurrogate`.

---

# Versalschrift mit SS entkommt der Term-Liste

Ein Term `Straßburger` mit `IgnoreCase` findet `straßburger`, aber nicht `STRASSBURGER`. Das scharfe s hat keine einbuchstabige Großform, und Go faltet die Schreibweisen nicht ineinander. In Versalzeilen — Formularen, Adressblöcken, Ausweisdaten — geht ein Name so im Klartext hinaus.

Reproduktion: `TestUnicode_SharpSCaseFolding`, protokolliert alle drei Schreibungen. Der Test ist bewusst grün, er dokumentiert nur; ob das behoben wird, ist eine Abwägung. Eine Kur wäre, für Terme mit `ß` zusätzlich die `ss`-Schreibung in die Literalsuche aufzunehmen.

---

# Ein Term mit Sonderzeichen kommt als Kommando zurück

Der Ersatzwert ist immer ein harmloses Einzelwort, der Originalwert nicht unbedingt. Das Modell sieht `d-abe950cb6234`, hat keinen Grund zu quotieren und schreibt `ls /mnt/d-abe950cb6234/`. Der Restorer setzt den Originalwert ein, und in der Shell des Nutzers steht `ls /mnt/kunde x & co/` — ein Kommando im Hintergrund und ein zweites hinterher. Dasselbe mit `;`, mit Backtick und mit `$( )`. Quotiert das Modell den Ersatzwert, hilft das gegen diese vier, aber nicht gegen den Apostroph: aus `grep 'A-1234'` wird `grep 'Sean O'Connor'`, und die Anführung kippt.

Es ist kein Leck und auch keine Einschleusung von außen — der Originalwert steht in der Term-Liste des Nutzers, niemand Fremdes bestimmt ihn. Es ist eine Formänderung zwischen dem, was das Modell geschrieben hat, und dem, was ausgeführt wird. Im Normalbetrieb sieht der Nutzer den wiederhergestellten Befehl in der Rückfrage, bevor er läuft; im automatischen Modus sieht er ihn nicht.

Reproduktion: `TestAdmin_UnquotedAliasInCommand` für die unquotierte Stelle, `TestAdmin_TermWithShellMetacharacters` für die quotierte. Beide sind grün, sie halten das Verhalten fest.

Vorschlag: beim Laden der Term-Liste eine Warnung für Werte, die `'`, `"`, Backtick, `$`, `;`, `&`, `|`, `<`, `>`, Zeilenumbruch oder Tabulator enthalten. Kein Startfehler, denn ein solcher Wert kann gewollt sein. Das Leerzeichen bleibt draußen, Personennamen tragen es regulär; dafür genügt ein Satz im README unter „Grenzen“.

Die Kommandozeile ist dabei nur der auffälligste Ort. Der Rückweg schreibt den Originalwert in jeden Text, den der Client weiterverarbeitet, und jedes Zeichen mit Sonderbedeutung wirkt dort, wo es landet. Ein Zeilenumbruch im Wert bricht die Zeile eines Patches, einer Konfigurationsdatei und eines Kommentars auseinander, und aus einem Kommentar wird dabei ausführbarer Text. Ein Wagenrücklauf zeigt in der Rückfrage einen anderen Befehl an, als anschließend ausgeführt wird — die Anzeige überschreibt sich selbst. Ein Doppelkreuz im Wert kürzt eine Konfigurationszeile stillschweigend, ein Prozentzeichen schneidet eine crontab-Zeile ab, ein Schrägstrich legt eine Datei ein Verzeichnis tiefer ab als vorgesehen. Gerät der Wert in ein Suchmuster oder in eine `sed`-Ersetzung, die das Modell gebaut hat, sucht und ersetzt sie etwas anderes; gerät er in JSON, das das Modell geschrieben hat, zerstören Anführungszeichen und Rückstrich den Body.

Diese Fälle teilen eine Ursache und eine Kur: das Modell quotiert nach dem, was es sieht, und der Restorer setzt etwas ein, das anders quotiert werden müsste. Reproduktion im Paket `harm`, elf rote Tests von zwanzig, jeder für einen Zielkontext. Der Unterschied zum Rest der Familie ist wichtig: der Wagenrücklauf und das Doppelkreuz verstümmeln still, der Zeilenumbruch und der Schrägstrich fallen auf. Still ist schlimmer.

---

# Regex-Terme und Adressmuster greifen weiter, als sie sollen

Ein Term mit `Regex` statt `Value` wird ohne Wortgrenzen angewandt und trifft deshalb mitten im Token: der Ausdruck ersetzt einen Teil eines längeren Wortes und lässt den Rest stehen — dieselbe Wirkung wie beim Teiltreffer, nur aus der Konfiguration heraus. Wer die Term-Liste mit Ausdrücken pflegt, muss die Grenzen also selbst in den Ausdruck schreiben, und nichts sagt ihm das.

Zwei Terme, die im Text unmittelbar aneinandergrenzen, verkleben ihre Ersatzwerte zu einem Wort. Der Rückweg kann das nicht mehr trennen, weil die Grenze fehlt, an der er ansetzen müsste; der Round-Trip bricht. Gefunden hat das der Fuzz-Lauf, nicht ein ausgedachter Fall.

Die Adressmuster greifen in längere Zahlenketten hinein: eine Folge von Ziffern und Punkten, die vier passende Gruppen enthält, wird als Adresse gemeldet, auch wenn sie Teil einer längeren Kette ist. Das ist die Verwandtschaft der vierstelligen Versionsnummer aus den Beobachtungen, hier aber ohne die Entschuldigung, dass es eine gültige Adresse wäre.

Reproduktion im Paket `props`: `TestProps_RegexTermInsideAToken`, `TestProps_TouchingTermsGlueTheirPseudonyms`, `TestProps_AddressInsideALongerRun` und `TestProps_CidrTermWithABrokenWildcard`, alle rot, dazu drei Fuzz-Ziele mit Korpus. Der Fuzz-Lauf über den Round-Trip hat die verklebten Ersatzwerte selbständig gefunden.

Vorschlag: für Regex-Terme entweder die Wortgrenzen erzwingen oder beim Laden warnen, wenn ein Ausdruck keine trägt. Die verklebten Ersatzwerte lassen sich nur beim Erzeugen lösen — ein Trennzeichen, das im Ersatzwert nicht vorkommt, oder die Weigerung, zwei Treffer ohne Trennzeichen dazwischen beide zu ersetzen. Die Zahlenketten löst eine Prüfung auf das Zeichen vor und nach dem Treffer.

---

# Was die Konfiguration stillschweigend annimmt

Fünf Stellen, an denen ein falsch gemeinter Eintrag angenommen wird und nichts tut oder etwas anderes tut als gedacht.

Ein Eintrag in `path.preserve`, der einen Pfad statt eines Segments enthält, wird angenommen und wirkt nie. Alle vier geprüften Formen gehen still durch, mit führendem Schrägstrich, mit abschließendem, mit zwei Segmenten und als Glob. Der Nutzer liest seine eigene Konfiguration, sieht das Verzeichnis dort stehen und wundert sich, dass es weiterhin ersetzt wird. Die Kur ist, solche Einträge in `NewPaths` zurückzuweisen und den Eintrag in der Meldung im Klartext zu nennen.

Die Rechte der Schlüsseldatei sieht sich niemand an. Sie entsteht beim Ausrollen von Hand, ein zu großzügiger Modus fällt an keiner Stelle auf, und aus dem Salt-Schlüssel lassen sich alle Ersatzwerte einer Sitzung nachrechnen. Drei Zeilen über `os.Stat` genügen, um es zu halten wie ssh: bei Leserecht für Gruppe oder andere abbrechen oder mindestens warnen.

Der Pfad des Schlüssels wird relativ, wenn das Plugin-Verzeichnis nicht zu ermitteln ist. Dann fehlt entweder die Datei und die Registrierung bricht mit einem nichtssagenden Pfad ab, oder es liegt zufällig eine im Arbeitsverzeichnis und wird genommen. Ein nicht absolutes Ergebnis sollte zurückgewiesen werden, und der konfigurierte Wert vor dem Auflösen getrimmt.

Die Mindestlänge des Salt-Schlüssels prüft nur der Lader, nicht `NewGenerator`. Im Betrieb hält die Regel, weil `main.go` über den Lader geht; im Vertrag von `NewGenerator` steht sie nicht, und ein künftiger Aufrufer erfährt es nicht.

Die Meldung für eine falsche Art in der Term-Liste nennt keine richtige und zeigt auf einen Index statt auf eine Zeile. Bei einer Datei mit einigen hundert Zeilen muss der Nutzer abzählen. Die erlaubten Arten stehen ohnehin in `Kind.Valid`, und die Zeilennummer kennt der Lader.

Reproduktion im Paket `config`, 32 Proben, davon eine rot: `TestConfig_PathsPreserveEntriesThatCannotMatch`. Die übrigen vier sind grün und protokollieren, weil sie Härtungen betreffen und keine Fehler.

---

# Beobachtungen ohne Fehlerstatus

`Walk` verwirft alles, was nach der schließenden Klammer steht, sobald eine Ersetzung stattfindet: aus `{"a":"zeus.lan"}trailing` wird `{"a":"h-0123456789ab"}`, und aus zwei aufeinanderfolgenden Objekten bleibt das erste. Der Produktionsweg ist davon nicht betroffen, weil `ReplaceStrings` denselben Body mit `body is not a JSON object` ablehnt und auf dem Hinweg `on_error: block` gilt. Es bleibt eine Inkonsistenz zwischen zwei Funktionen desselben Pakets, die einen späteren Aufrufer in die Falle laufen lässt. `TestWalk_TrailingBytesAfterObject` hält sie fest.

Eine Ersetzung sortiert die Schlüssel des Objekts alphabetisch um und schreibt Escapes neu: aus `ü` wird `ü`. Beides ist deterministisch — zwanzig Läufe liefern dasselbe Byte für Byte — und semantisch folgenlos, weil JSON-Objekte ungeordnet sind und beide Schreibweisen dasselbe Zeichen meinen. Festgehalten in `TestWalk_ReserializationIsDeterministic`.

Ein Personen-Ersatzname ist ein gewöhnlicher Name. Schreibt das Modell ihn aus eigenem Antrieb, macht der Restorer daraus den echten: aus einem beiläufigen Satz über `Paula Wehrle` wurde einer über die reale Person. Das ist der Preis der Formtreue und lässt sich nur über die Namensauswahl kleinhalten. `TestPerson_PseudonymCollidesWithOrdinaryText` dokumentiert es.

Der Kommentar über `WordBoundary` in `detect/terms.go` beschreibt noch die Regel vor `8436b9e`, nach der ein Unterstrich ein Wortzeichen sei. Das Verhalten ist richtig, die Beschreibung veraltet.

`Restorer()` friert die Zeilen beim ersten Aufruf ein; das steht so im Vertrag, und der Hinweg ist vorher fertig. Die Falle ist die Stille: ein `Lookup` nach dem Einfrieren gelingt, liefert einen Ersatzwert, trägt ihn ein — und der Restorer sieht ihn nie. Wer die Reihenfolge künftig umbaut, bekommt keinen Fehler, sondern eine Antwort voller Ersatzwerte. Eine Zählung oder ein Protokolleintrag für diesen Fall kostet nichts. `TestRestorer_FreezeIsSilent` und `TestRestorer_HandleTakenTooEarly` halten beide Richtungen fest, `TestRestorer_FillThenRestore` die richtige Reihenfolge.

Eine vierstellige Versionsnummer, deren Teile alle unter 256 liegen, ist von einer Adresse nicht zu unterscheiden und wird ersetzt. Drei Teile bleiben unberührt, ebenso alles mit einem Teil über 255, was die meisten Firmware- und Windows-Nummern ausschließt. Kein Leck, aber das Modell liest eine Adresse, wo eine Version steht. `TestRange_VersionNumbersAreNotAddresses`.

Die Musterebene übergeht die Adressen, die in Handbüchern stehen: die drei Dokumentationsnetze, Loopback, die unbestimmte Adresse, die Rundsendeadresse, Link-Local und Multicast. Ein eingefügtes Handbuch erzeugt also kein Rauschen. `TestRange_WhatThePatternLayerReports` listet die Entscheidung Bereich für Bereich.

Der Rückweg unterscheidet nach Art des Ersatzwertes: die strukturellen Formen kommen auch in Versalien zurück, ein Personen-Ersatzname nur in seiner eigenen Schreibung. Beides ist plausibel — das Modell schreibt Rechnernamen gern groß, und ein Name in Versalien wäre ein anderes Wort —, steht aber nirgends geschrieben. `TestCC_PseudonymAsTheModelWritesIt` und `TestCC_PersonPseudonymIgnoresCase`.

Was das Modell am Ersatzwert selbst ändert, ist verloren: ein Umbruch mitten im Wort, ein eingefügtes Leerzeichen, eine Kürzung mit Auslassungspunkten. Der Ersatzwert bleibt dann beim Nutzer stehen. Das ist die Kehrseite der Formtreue und nicht zu beheben; es zu kennen hilft beim Lesen einer Antwort, in der ein einzelnes Kürzel übrig geblieben ist.

`KindURL` hat keinen eigenen Renderer und fällt auf das undurchsichtige Token zurück, das sonst Zugangsdaten bekommen. Aus einer Adresse wird damit ein Wort, mit dem das Modell nicht arbeiten kann: es kann keinen Pfad anhängen, keinen Parameter ändern, keine zweite Adresse derselben Herkunft zuordnen. Das Muster ist standardmäßig aus, die Sache also nicht dringend; wer es einschaltet, sollte wissen, was er eintauscht. Eine Adresse zerfällt sauber in Schema, Rechnername und Pfadsegmente, für die es Renderer längst gibt. `TestForm_EveryKindKeepsItsShape` hält es fest, als einziger roter Punkt unter siebzehn Arten.

Der Stream stellt vier benannte Felder wieder her, der Weg am Stück jeden Wert, den die Sperrliste nicht deckt. Beides ist so dokumentiert, aber die zwei Wege sagen damit Verschiedenes über denselben Body: die Meldung eines Fehlerereignisses, ein `content_block_start` vom Typ `tool_use` mit vorbelegtem `input` und der Inhalt eines Suchergebnisses behalten ihre Ersatzwerte. Nach dem Kapitel über den Gesprächsverlauf bleiben die dann für immer stehen. Der Denkblock bleibt in beiden Wegen richtigerweise unangetastet.

Der Stream löst die Neukodierung eines Ereignisses viel häufiger aus als der Weg am Stück: ein Delta ohne eigenen Treffer wird neu geschrieben, sobald der Nachbar etwas zurückhielt, und ein halbes Surrogat darin verschwindet dabei schon auf der Leitung. Der Befund selbst steht oben; neu ist, wie leicht der Stream ihn erreicht.

Ein `content_block_stop` ohne Index leert den Rückhalt jedes offenen Blocks, weil derselbe Wert minus eins zugleich „kein Index“ und „alle Blöcke“ bedeutet. Die API schickt den Index immer mit; es ist eine Härtung, kein Betriebsfehler.

Die Vorschicht, die Mailadressen befördert, wächst quadratisch mit der Zahl der Adressen im Text, weil sie für jeden Mailtreffer alle Treffer der früheren Schichten durchläuft. Ein Mailserver-Protokoll mit dem Rechnernamen in jeder Zeile ist genau dieser Fall und im Alltag der Normalfall; bei viertausend Zeilen wird es messbar. Einmal je Scan nach Startposition sortieren und binär suchen genügt. Dieselbe Vorschicht nimmt einem Term seine Art, wenn der Term selbst eine vollständige Mailadresse ist: er kommt dann als Adresse zurück, nicht als Name. Und der Vertrag von `Composite` beschreibt die Vorschicht überhaupt nicht, was die nächste Änderung an der Rangfolge unnötig schwer macht.

Ein geschachteltes `Composite` verliert die Abschirmung: das Merkmal, das einen ausgeschlossenen Treffer kennzeichnet, überlebt die Grenze nicht. Heute schachtelt niemand; wer es tut, sollte es wissen.

---

# Was hält

Der Round-Trip überstand jede geprüfte Umgebung: Anführungszeichen, Klammern, Doppelpunkt, Schrägstrich, Gedankenstrich, Zeilenumbruch, URL, mehrfaches Vorkommen. Ein zweiter Durchlauf über bereits ersetzten Text ändert nichts, das Wiederherstellen ist idempotent, überlappende Terme lösen sich nach der längeren Übereinstimmung auf, und ein Literal mit Regex-Metazeichen wird literal behandelt. Die zerlegte Unicode-Schreibweise wird erkannt und kommt unverändert zurück, ein Text ohne Treffer bleibt Byte für Byte gleich.

Auf der JSON-Seite bleiben Zahlenschreibweisen erhalten, auch `1e400` und dreißigstellige Ganzzahlen. Fünftausend Verschachtelungsebenen laufen ohne Absturz durch. Der SSE-Parser nimmt CRLF, fehlendes Leerzeichen nach `data:`, führende Kommentarzeilen und Ereignisse ohne `event:`-Zeile. Die doppelte Kodierung in `partial_json` übersteht Anführungszeichen, Backslash, Tabulator und Emoji unbeschadet, und ein Ersatzwert mit JSON-Metazeichen zerstört den Body nicht. Bodies mit führendem oder abschließendem Leerraum werden angenommen und der Leerraum erhalten.

Auf der Betriebsseite kam derselbe Rechnername unverändert zurück, gleich ob er hinter `ssh`, in einer `scp`-Quelle mit Doppelpunkt, in einer URL mit Port, in einem `Host`-Block, in `/etc/hosts`, hinter `ProxyJump=`, in `ssh://` für Docker, als Präfix eines Sicherungsdateinamens oder als Wert einer Umgebungsvariable stand; in keiner der dreizehn Formen blieb das Original sichtbar. Adressen behalten Port, Präfixlänge und die IPv6-Klammern, eine MAC bleibt eine MAC. Die acht geprüften Konfigurationsformen — YAML mit und ohne Anführungszeichen, INI, Listenpunkt, `DATABASE_URL`, systemd-`ExecStart`, `/etc/hosts` mit Kommentar und ein JSON-Feld — laufen sauber hin und zurück. Spaltenbündige Ausgaben verrutschen, weil der Ersatzwert länger ist als der Rechnername; der Text bleibt richtig, nur die Tabelle sieht schief aus.

Nebenläufigkeit und Maßstab geben keinen Anlass zur Sorge. Der Race-Detektor bleibt still, während zweiunddreißig Goroutinen in dieselbe Tabelle schreiben und zweiunddreißig weitere daraus wiederherstellen, und ebenso beim Ablegen, Holen, Löschen und Kehren im Speicher aus sechzehn Richtungen. Ein Protokoll aus zwanzigtausend Zeilen und 1,6 Megabyte läuft in 150 Millisekunden durch den Hinweg und in 44 durch den Rückweg; die Tabelle hat danach zwanzigtausend Einträge, und ein Stück der Antwort dagegen zu prüfen kostet weniger als eine Mikrosekunde. Ein Bildschirmfoto von 1,8 Megabyte als base64 im Body ist in acht Millisekunden abgearbeitet, mit und ohne Treffer. Die Grenzen des Verfahrens liegen also nicht bei der Rechenzeit. Ein Ersatzwert je Wert bleibt allerdings für immer in der Tabelle, auch der aus einem einmal eingefügten Protokoll; bei zwanzigtausend Einträgen fällt das nicht auf, eine Obergrenze gibt es aber nicht.

Der Fragment-Round-Trip hält, worauf ein Editierwerkzeug angewiesen ist: eine einzelne Zeile, eine Zeile ohne Zeilenumbruch, der nackte Ersatzwert, derselbe mit Doppelpunkt und Port, in Anführungszeichen und über zwei Zeilen kommen alle byte-genau zurück, und ein Patch mit Hunk-Kopf, Kontextzeilen und leerer Kontextzeile passt hinterher noch. Compilermeldungen und Stapelabzüge behalten Zeile und Spalte, gleich ob der Pfad absolut, relativ, eingerückt oder in Anführungszeichen steht.

Der Denkblock bleibt unangetastet, in jeder geprüften Position: oben im Baum, zweifach verschachtelt, in der geschwärzten Fassung und neben einem Geschwisterelement, das im selben Durchgang richtig gefiltert wird. Werkzeugname, `metadata.user_id` und Modellname bleiben ebenfalls stehen, während Nutzertext, Systemtext, Werkzeugbeschreibung, `tool_use.input` und Werkzeugergebnis ersetzt werden.

Die Pfadebene bringt jede erkannte Form unverändert zurück, doppelte Schrägstriche, `..`, Tilde, Leerzeichen im Dateinamen und Umlaute eingeschlossen, und ihre Bewahrliste kennt fünfundzwanzig der dreißig Verzeichnisnamen, die in jedem Projekt vorkommen; ersetzt werden nur die projekteigenen. Dateinamen bleiben lesbar, ein Term innerhalb eines Dateinamens wird trotzdem gefunden.

Der Namensraum hält dem Druck stand: zweiundsiebzig Namen im Vorrat, hundertvierundvierzig Personen im Text, hundertvierundvierzig verschiedene Ersatznamen und keine Kollision; jeder löst sich auf die Person auf, für die er gemacht wurde, und ein Name, den der Nutzer selbst schützen lässt, wird nicht mehr ausgegeben. Der Salt bleibt über das wachsende Gespräch derselbe, mit Kopfzeile wie ohne, und zwei Gespräche teilen ihn nicht. Der Rückhalt schneidet nie mitten durch ein Zeichen, auch nicht bei Emoji oder chinesischer Schrift.

Die Formtreue trägt durch alle siebzehn Arten bis auf die Adresse. Eine Ersatz-IBAN hat dasselbe Länderkürzel, dieselbe Länge und eine gültige Prüfsumme nach mod 97; eine UUID behält die Gruppierung 8-4-4-4-12, ein Fingerabdruck seine dreiundvierzig Zeichen hinter `SHA256:`, eine MAC ihre sechs Paare, ein Dateiname seine Endung und eine Netzmaske ihre Präfixlänge. Derselbe Wert unter zwei Arten bekommt zwei Ersatzwerte, und beide lösen sich richtig auf.

Der Stream trägt seine gewöhnliche Arbeit ohne Verlust. Ein Block, der in Fragmenten von drei Byte ankommt, ergibt beim Client denselben Text wie am Stück restauriert, und die Reihenfolge der Ereignisse bleibt erhalten. Ein Block aus lauter Ein-Zeichen-Deltas kommt vollständig an, obwohl unterwegs 41 von 70 Fragmenten in den Rückhalt fallen. Zwei gleichzeitig offene Blöcke halten getrennte Rückhalte, jedes Stop-Ereignis leert nur seinen eigenen, und ein Ersatzwert auf der Naht zwischen zwei Blöcken wird in seine eigene Hälfte ausgespült. Keep-alives ändern nichts, gleich ob sie eigenständig kommen oder an einem Delta kleben, gestörte Reihenfolgen verlieren nichts, und die Fragmente eines Werkzeugaufrufs ergeben bei jeder Schnittbreite von einem bis sieben Byte wieder gültiges JSON, auch wenn der Originalwert ein Anführungszeichen trägt.

Die Eigenschaften halten auch über zufällige Eingaben. Zehn Fuzz-Ziele prüfen den Round-Trip über Terme, Muster, Ausdrücke und das Composite, die Grenzen des Rückhalts, die Form der Ersatzwerte und die Trennung der Werte in der Tabelle; die Läufe fanden genau die Fälle, die oben als Befunde stehen, und darüber hinaus nichts. Das ist der eigentliche Wert dieses Bereichs: die bekannten Grenzfälle sind vollständig, nicht nur zahlreich.

---

# Was dieses Labor nicht erreicht

Von außen erreichbar sind `detect`, `pseudo`, `mapping` und `payload`. Nicht erreichbar sind der Interceptor, `stream.go`, der Lader der Term-Datei, die Prüfung der Konfiguration und das Prüfprotokoll: sie liegen in `package main`, und `internal/*` sperrt Go ohnehin. Der Ablauf des Streams ist deshalb in `stream/rebuild.go` nachgebaut, Zeile für Zeile nach der Vorlage, und die Befunde des Stream-Kapitels stehen und fallen mit der Treue dieses Nachbaus. Er lässt weg, was sich von außen nicht nachbilden lässt: den Mutex, den Panik-Auffang, das Protokoll und den Zugriff auf den Tabellenspeicher. Ungeprüft bleiben damit die Nebenläufigkeit eines Streamzustands unter den Aufrufen des Hosts, das Aufräumen am Ende eines Streams und die Frage, ob der Host einen fehlerhaften Chunk wirklich unverändert weiterreicht und einen unterdrückten wirklich unterdrückt.

Ebenso offen ist der Weg durch den echten HTTP-Pfad: ob `on_error: block` bei einem fehlerhaften Body wirklich blockt, ob die Grenze von zweiunddreißig Megabyte sauber greift, was ein mitten im Stream abgebrochener Anbieter mit dem zurückgehaltenen Rest macht, und ob das Prüfprotokoll schreibt, was es schreiben soll. Dass ein `content_block_start` mit gefülltem `input` oder ein Suchergebnis über den Stream kommt, ist der Schnittstellenbeschreibung entnommen und nicht an einem Mitschnitt belegt; für den Wortlaut einer Fehlermeldung gilt dasselbe.

Ebenfalls offen: betterleaks hinter seinem Build-Tag, die Erkennung von Zugangsdaten also, und alles, was nicht dem Anthropic-Schema folgt. Die Race beim Neuladen der Konfiguration im laufenden Host, der Punkt aus dem Übergabedokument, ist hier nicht zu prüfen; was geprüft ist, ist die Nebenläufigkeit der Bausteine, und die hält.
