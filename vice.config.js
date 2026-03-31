export default {
  ignore: ['legacy/', 'migrations/'],
  headers: { url: 'https://monsite.be' },
  ci: { failOnCritical: true, minGrade: 'C' },
  extraPatterns: []
}
