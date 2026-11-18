import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.w3c.dom.Element

/**
 * Writes a JaCoCo XML report as lcov, the format that diff-cover and the commons coverage tools read.
 *
 * Each SF path is relative to the repository root, so it matches the paths in a git diff.
 * JaCoCo counts a line's covered and missed branches but does not say which is which.
 * So a line with 2 covered and 1 missed branch gets 2 taken and 1 untaken BRDA record.
 */
abstract class JacocoLcov : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val report: ConfigurableFileCollection

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sourceDirectories: ConfigurableFileCollection

    @get:Internal
    abstract val repositoryRoot: DirectoryProperty

    @get:OutputFile
    abstract val lcov: RegularFileProperty

    @TaskAction
    fun write() {
        val root = repositoryRoot.get().asFile
        val out = StringBuilder()
        var lines = 0
        var linesHit = 0
        var branches = 0
        var branchesHit = 0
        // No report means the library has no tests or no code yet, so the lcov file is empty.
        for (xml in report.files.filter { it.isFile }) {
            val packages = parse(xml).getElementsByTagName("package")
            for (pkg in (0 until packages.length).map { packages.item(it) as Element }) {
                for (sourceFile in elements(pkg, "sourcefile")) {
                    val relative = pkg.getAttribute("name") + "/" + sourceFile.getAttribute("name")
                    val path = sourceDirectories.files.map { File(it, relative) }.firstOrNull { it.isFile }
                        ?: throw IllegalStateException("no source file $relative in ${sourceDirectories.files}")
                    out.append("SF:").append(path.relativeTo(root).invariantSeparatorsPath).append('\n')
                    for (line in elements(sourceFile, "line")) {
                        val number = line.getAttribute("nr")
                        val ran = line.getAttribute("ci").toInt() > 0
                        val covered = line.getAttribute("cb").toInt()
                        val missed = line.getAttribute("mb").toInt()
                        out.append("DA:$number,${if (ran) 1 else 0}\n")
                        lines++
                        if (ran) linesHit++
                        for (i in 0 until covered + missed) {
                            // "-" marks a branch on a line that never ran.
                            val taken = if (i < covered) "1" else if (ran) "0" else "-"
                            out.append("BRDA:$number,0,$i,$taken\n")
                        }
                        branches += covered + missed
                        branchesHit += covered
                    }
                    out.append("end_of_record\n")
                }
            }
        }
        lcov.get().asFile.writeText(out.toString())
        logger.lifecycle("line coverage: $linesHit of $lines lines, branch coverage: $branchesHit of $branches branches")
    }

    private fun parse(xml: File) =
        DocumentBuilderFactory.newInstance().apply {
            // The report names report.dtd, which is not on disk.
            setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        }.newDocumentBuilder().parse(xml)

    private fun elements(parent: Element, tag: String): List<Element> {
        val nodes = parent.childNodes
        return (0 until nodes.length).map { nodes.item(it) }.filterIsInstance<Element>().filter { it.tagName == tag }
    }
}
